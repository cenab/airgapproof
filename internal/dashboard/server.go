package dashboard

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cenab/airgapproof/internal/report"
)

type Server struct {
	Store     *Store
	AdminHash [32]byte
	PublicURL string
	secure    bool
}
type principal struct {
	Team  Team
	Admin bool
	Token string
}

func New(store *Store, adminToken, publicURL string) (*Server, error) {
	if len(adminToken) < 32 {
		return nil, errors.New("dashboard admin token must contain at least 32 characters")
	}
	u, err := url.Parse(publicURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("public URL must be an absolute HTTP(S) URL")
	}
	return &Server{Store: store, AdminHash: sha256.Sum256([]byte(adminToken)), PublicURL: strings.TrimRight(publicURL, "/"), secure: u.Scheme == "https"}, nil
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if s.Store.DB.Ping(ctx) != nil {
			http.Error(w, "Database unavailable", 503)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.auth(s.logout))
	mux.HandleFunc("GET /{$}", s.auth(s.home))
	mux.HandleFunc("POST /upload", s.auth(s.upload))
	mux.HandleFunc("GET /runs/{id}", s.auth(s.view))
	mux.HandleFunc("GET /compare", s.auth(s.comparisonPage))
	mux.HandleFunc("GET /api/teams", s.auth(s.teams))
	mux.HandleFunc("POST /api/teams", s.auth(s.createTeam))
	mux.HandleFunc("PUT /api/teams/{id}/policy", s.auth(s.setPolicy))
	mux.HandleFunc("POST /api/teams/{id}/rotate", s.auth(s.rotate))
	mux.HandleFunc("GET /api/runs", s.auth(s.listRuns))
	mux.HandleFunc("POST /api/runs", s.auth(s.addRun))
	mux.HandleFunc("GET /api/runs/{id}", s.auth(s.getRun))
	mux.HandleFunc("GET /api/compare", s.auth(s.compare))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		mux.ServeHTTP(w, r)
	})
}
func (s *Server) identity(ctx context.Context, token string) (principal, error) {
	p := principal{Token: token}
	if len(token) < 32 || len(token) > 256 {
		return p, errors.New("invalid token")
	}
	hash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(hash[:], s.AdminHash[:]) == 1 {
		p.Admin = true
		return p, nil
	}
	team, err := s.Store.TeamByToken(ctx, token)
	p.Team = team
	return p, err
}
func csrf(token string) string {
	h := hmac.New(sha256.New, []byte(token))
	_, _ = h.Write([]byte("airgapproof-browser-csrf-v1"))
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Server) auth(next func(http.ResponseWriter, *http.Request, principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := ""
		bearer := false
		if header := r.Header.Get("Authorization"); header != "" {
			scheme, value, ok := strings.Cut(header, " ")
			if !ok || scheme != "Bearer" {
				http.Error(w, "Bearer token required", 401)
				return
			}
			token = value
			bearer = true
		} else if c, err := r.Cookie("ap_session"); err == nil {
			token = c.Value
		}
		p, err := s.identity(r.Context(), token)
		if err != nil {
			if !strings.HasPrefix(r.URL.Path, "/api/") && r.Method == "GET" {
				http.Redirect(w, r, "/login", 303)
			} else {
				http.Error(w, "Authentication required", 401)
			}
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && !bearer {
			if origin := r.Header.Get("Origin"); origin != "" && origin != s.PublicURL {
				http.Error(w, "Origin rejected", 403)
				return
			}
			value := r.Header.Get("X-CSRF-Token")
			if value == "" {
				value = r.FormValue("_csrf")
			}
			if !hmac.Equal([]byte(value), []byte(csrf(token))) {
				http.Error(w, "Request token rejected; reload the form", 403)
				return
			}
		}
		next(w, r, p)
	}
}
func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errors.New("invalid JSON request")
	}
	var more any
	if d.Decode(&more) != io.EOF {
		return errors.New("expected one JSON document")
	}
	return nil
}
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.ExecuteTemplate(w, "login", nil)
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != s.PublicURL {
		http.Error(w, "Origin rejected", 403)
		return
	}
	token := r.FormValue("token")
	if _, err := s.identity(r.Context(), token); err != nil {
		http.Error(w, "Token is invalid or has been rotated", 401)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "ap_session", Value: token, Path: "/", HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 60 * 60})
	http.Redirect(w, r, "/", 303)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request, p principal) {
	http.SetCookie(w, &http.Cookie{Name: "ap_session", Path: "/", HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	http.Redirect(w, r, "/login", 303)
}
func (s *Server) teamID(r *http.Request, p principal) (int64, error) {
	if !p.Admin {
		if v := r.URL.Query().Get("team"); v != "" && v != fmt.Sprint(p.Team.ID) {
			return 0, errors.New("team access denied")
		}
		return p.Team.ID, nil
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("team"), 10, 64)
	if err != nil || id < 1 {
		return 0, errors.New("admin requests require a positive team query parameter")
	}
	return id, nil
}
func (s *Server) teams(w http.ResponseWriter, r *http.Request, p principal) {
	if !p.Admin {
		jsonResponse(w, 200, []Team{p.Team})
		return
	}
	teams, err := s.Store.Teams(r.Context())
	if err != nil {
		http.Error(w, "Cannot read teams", 500)
		return
	}
	jsonResponse(w, 200, teams)
}
func (s *Server) createTeam(w http.ResponseWriter, r *http.Request, p principal) {
	if !p.Admin {
		http.Error(w, "Admin token required", 403)
		return
	}
	var body struct {
		Name   string `json:"name"`
		Policy Policy `json:"policy"`
	}
	if err := decode(r, &body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	team, token, err := s.Store.CreateTeam(r.Context(), body.Name, body.Policy)
	if err != nil {
		http.Error(w, "Cannot create team; check its unique name and policy", 400)
		return
	}
	jsonResponse(w, 201, map[string]any{"team": team, "token": token})
}
func (s *Server) setPolicy(w http.ResponseWriter, r *http.Request, p principal) {
	if !p.Admin {
		http.Error(w, "Admin token required", 403)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var policy Policy
	if err != nil || decode(r, &policy) != nil || s.Store.SetPolicy(r.Context(), id, policy) != nil {
		http.Error(w, "Invalid team or policy", 400)
		return
	}
	jsonResponse(w, 200, policy)
}
func (s *Server) rotate(w http.ResponseWriter, r *http.Request, p principal) {
	if !p.Admin {
		http.Error(w, "Admin token required", 403)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid team", 400)
		return
	}
	token, err := s.Store.Rotate(r.Context(), id)
	if err != nil {
		http.Error(w, "Team not found", 404)
		return
	}
	jsonResponse(w, 200, map[string]string{"token": token})
}
func (s *Server) listRuns(w http.ResponseWriter, r *http.Request, p principal) {
	id := p.Team.ID
	if !p.Admin && r.URL.Query().Get("team") != "" {
		var err error
		id, err = s.teamID(r, p)
		if err != nil {
			http.Error(w, err.Error(), 403)
			return
		}
	}
	if p.Admin && r.URL.Query().Get("team") != "" {
		var err error
		id, err = s.teamID(r, p)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}
	runs, err := s.Store.Runs(r.Context(), id, r.URL.Query().Get("application"))
	if err != nil {
		http.Error(w, "Cannot read run history", 500)
		return
	}
	jsonResponse(w, 200, runs)
}
func (s *Server) addRun(w http.ResponseWriter, r *http.Request, p principal) {
	if p.Admin {
		http.Error(w, "Upload reports with a team token", 403)
		return
	}
	var evidence report.Report
	if err := decode(r, &evidence); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	saved, err := s.Store.AddRun(r.Context(), p.Team, &evidence)
	if err != nil {
		http.Error(w, "Invalid evidence, signature, or duplicate run ID", 400)
		return
	}
	jsonResponse(w, 201, saved)
}
func (s *Server) getRun(w http.ResponseWriter, r *http.Request, p principal) {
	id, err := s.teamID(r, p)
	if err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	saved, err := s.Store.Get(r.Context(), id, r.PathValue("id"))
	if err != nil {
		http.Error(w, "Run not found", 404)
		return
	}
	jsonResponse(w, 200, saved)
}
func (s *Server) comparison(r *http.Request, p principal) (Comparison, error) {
	id, err := s.teamID(r, p)
	if err != nil {
		return Comparison{}, err
	}
	base, err := s.Store.Get(r.Context(), id, r.URL.Query().Get("base"))
	if err != nil {
		return Comparison{}, err
	}
	head, err := s.Store.Get(r.Context(), id, r.URL.Query().Get("head"))
	if err != nil {
		return Comparison{}, err
	}
	if base.Application != head.Application {
		return Comparison{}, errors.New("runs belong to different applications")
	}
	return Compare(base.Report, head.Report), nil
}
func (s *Server) compare(w http.ResponseWriter, r *http.Request, p principal) {
	c, err := s.comparison(r, p)
	if err != nil {
		http.Error(w, "Comparison requires two accessible runs from the same application and team", 400)
		return
	}
	jsonResponse(w, 200, c)
}
func (s *Server) home(w http.ResponseWriter, r *http.Request, p principal) {
	id := p.Team.ID
	teams := []Team{p.Team}
	if p.Admin {
		var err error
		teams, err = s.Store.Teams(r.Context())
		if err != nil {
			http.Error(w, "Cannot read teams", 500)
			return
		}
		id = 0
		if r.URL.Query().Get("team") != "" {
			id, err = s.teamID(r, p)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		}
	}
	runs, err := s.Store.Runs(r.Context(), id, r.URL.Query().Get("application"))
	if err != nil {
		http.Error(w, "Cannot read run history", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.ExecuteTemplate(w, "home", map[string]any{"Runs": runs, "Teams": teams, "Admin": p.Admin, "CSRF": csrf(p.Token), "TeamID": id, "Application": r.URL.Query().Get("application")})
}
func (s *Server) upload(w http.ResponseWriter, r *http.Request, p principal) {
	if p.Admin {
		http.Error(w, "Upload with a team token", 403)
		return
	}
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Report upload exceeds 10 MiB or is invalid", 400)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, _, err := r.FormFile("report")
	if err != nil {
		http.Error(w, "Choose a JSON report", 400)
		return
	}
	defer file.Close()
	var evidence report.Report
	d := json.NewDecoder(file)
	d.DisallowUnknownFields()
	if err = d.Decode(&evidence); err != nil {
		http.Error(w, "Invalid JSON report", 400)
		return
	}
	if _, err = s.Store.AddRun(r.Context(), p.Team, &evidence); err != nil {
		http.Error(w, "Invalid evidence or duplicate run", 400)
		return
	}
	http.Redirect(w, r, "/", 303)
}
func (s *Server) view(w http.ResponseWriter, r *http.Request, p principal) {
	id, err := s.teamID(r, p)
	if err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	saved, err := s.Store.Get(r.Context(), id, r.PathValue("id"))
	if err != nil {
		http.Error(w, "Run not found", 404)
		return
	}
	b, err := saved.Report.HTML()
	if err != nil {
		http.Error(w, "Cannot render report", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}
func (s *Server) comparisonPage(w http.ResponseWriter, r *http.Request, p principal) {
	c, err := s.comparison(r, p)
	if err != nil {
		http.Error(w, "Choose two runs from the same application and team", 400)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.ExecuteTemplate(w, "compare", c)
}

func Serve(ctx context.Context, listen, databaseURL, adminToken, publicURL string) error {
	store, err := Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer store.DB.Close()
	app, err := New(store, adminToken, publicURL)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: listen, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

var pages = template.Must(template.New("pages").Parse(`{{define "style"}}<style>:root{color-scheme:light;--ink:#173341;--muted:#49616c;--canvas:#edf3f5;--line:#c6d5dc;--accent:#075f78}*{box-sizing:border-box}body{margin:0;background:var(--canvas);color:var(--ink);font:16px/1.55 "Avenir Next",Avenir,"Segoe UI",sans-serif}header{background:#173341;color:white;padding:1.25rem 3vw;display:flex;gap:1.5rem;align-items:center;justify-content:space-between}header a{color:white}header strong{font-size:1.35rem}main{max-width:1280px;margin:auto;padding:2.5rem 3vw}h1{font-size:2.4rem;letter-spacing:-.04em;margin:0 0 .5rem}h2{font-size:1.35rem;margin:2rem 0 .75rem}p{max-width:72ch}.muted{color:var(--muted)}a{color:var(--accent);text-underline-offset:.2em}button{background:var(--accent);color:white;border:0;cursor:pointer}button,input,select{font:inherit;min-height:44px;padding:.55rem .8rem;border-radius:4px}input,select{border:1px solid #819da9;background:white;color:var(--ink);max-width:100%}label{font-weight:600;display:block;margin-bottom:.3rem}form.filters{display:flex;gap:1rem;align-items:end;flex-wrap:wrap;margin:1.5rem 0}form.filters>div{flex:1;min-width:12rem}table{border-collapse:collapse;width:100%;background:white}caption{text-align:left;padding:.6rem 0;color:var(--muted)}th,td{text-align:left;padding:1rem;border-bottom:1px solid var(--line);vertical-align:top}th{font-weight:600;color:var(--muted);font-size:.9rem}.table-scroll{overflow-x:auto}.badge{display:inline-block;font-size:.85rem;font-weight:700;padding:.15rem .55rem;border:1px solid #819da9;border-radius:4px;white-space:nowrap}.ready{color:#14623f;background:#edf9f2}.failed{color:#912b2b;background:#fff0f0}.upload{padding:1.5rem;background:white;max-width:48rem;margin-top:2rem;border-left:4px solid var(--accent)}.login{max-width:32rem;margin:8vh auto}.login input{width:100%;margin:.5rem 0 1rem}pre,code{overflow-wrap:anywhere}small{color:var(--muted)}:focus-visible{outline:3px solid #ac440d;outline-offset:3px}.skip{position:absolute;left:-9999px}.skip:focus{left:1rem;top:1rem;background:white;padding:1rem;z-index:10}details{margin:.75rem 0}summary{cursor:pointer;min-height:32px}@media(max-width:600px){main{padding:1.5rem 1rem}header{padding:1rem}h1{font-size:2rem}td,th{padding:.75rem}form.filters>div{min-width:100%}}</style>{{end}}{{define "head"}}<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AirgapProof</title>{{template "style"}}{{end}}{{define "login"}}{{template "head"}}<main class="login"><h1>AirgapProof</h1><p class="muted">Your offline deployment evidence, in one place.</p><h2>Sign in</h2><form action="/login" method="post"><label for="token">Team or administrator token</label><input id="token" name="token" type="password" required autocomplete="current-password" minlength="32"><button type="submit">Sign in</button></form><p class="muted">Ask your administrator for a team token. Keep it with your other deployment credentials.</p></main></html>{{end}}{{define "home"}}{{template "head"}}<a class="skip" href="#main">Skip to run history</a><header><strong>AirgapProof</strong><form action="/logout" method="post"><input type="hidden" name="_csrf" value="{{.CSRF}}"><button type="submit">Sign out</button></form></header><main id="main"><h1>Offline readiness</h1><p class="muted">Compare tested workflows, inspect external dependencies, and check release policies.</p><form class="filters" method="get" action="/">{{if .Admin}}<div><label for="team">Team</label><select id="team" name="team"><option value="">All teams</option>{{range .Teams}}<option value="{{.ID}}" {{if eq .ID $.TeamID}}selected{{end}}>{{.Name}}</option>{{end}}</select></div>{{end}}<div><label for="application">Application</label><input id="application" name="application" value="{{.Application}}"></div><button type="submit">Filter history</button></form><div class="table-scroll"><table><caption>Latest 100 received runs. Policy results are saved with each run.</caption><thead><tr><th scope="col">Application</th><th scope="col">Revision</th><th scope="col">Readiness</th><th scope="col">Policy</th><th scope="col">Tested at</th><th scope="col">Evidence</th></tr></thead><tbody>{{range .Runs}}<tr><td>{{.Application}}</td><td>{{if .Revision}}{{.Revision}}{{else}}Unspecified{{end}}</td><td><span class="badge {{if eq .Status "ready"}}ready{{else}}failed{{end}}">{{.Status}}</span></td><td>{{if .GatePassed}}Passed{{else}}Failed{{range .Decision.Reasons}}<details><summary>Reason</summary>{{.}}</details>{{end}}{{end}}</td><td>{{.CreatedAt.Format "2006-01-02 15:04 UTC"}}</td><td><a href="/runs/{{.ID}}?team={{.TeamID}}">View report</a><details><summary>Run ID</summary><code>{{.ID}}</code></details></td></tr>{{else}}<tr><td colspan="6">No runs yet. Upload a report or publish one from your CI pipeline.</td></tr>{{end}}</tbody></table></div>{{if not .Admin}}<section class="upload"><h2>Upload evidence</h2><form action="/upload" method="post" enctype="multipart/form-data"><input type="hidden" name="_csrf" value="{{.CSRF}}"><label for="report">JSON report, up to 10 MiB</label><input id="report" name="report" type="file" accept="application/json,.json" required><button type="submit">Upload report</button></form></section>{{end}}<section><h2>Compare releases</h2><p class="muted">Enter two run IDs for the same application and team.</p><form action="/compare" method="get" class="filters"><input type="hidden" name="team" value="{{.TeamID}}"><div><label for="base">Baseline run</label><input id="base" name="base" required pattern="[a-f0-9]{24}"></div><div><label for="head">New run</label><input id="head" name="head" required pattern="[a-f0-9]{24}"></div><button type="submit">Compare releases</button></form></section>{{if .Admin}}<section><h2>Team policies</h2><p>Create teams, rotate tokens, and update policies through the authenticated API. Tokens are shown only when created or rotated.</p>{{range .Teams}}<details><summary>{{.Name}} (team {{.ID}})</summary><p>Required scenarios: {{.Policy.MinScenarios}}. Disconnected VM: {{.Policy.RequireDisconnected}}. Tracing: {{.Policy.RequireTracing}}. Trusted signature: {{.Policy.RequireSignature}}.</p></details>{{end}}</section>{{end}}<p class="muted">A passing profile covers the workflows in its report. Untested behavior remains outside that result.</p></main></html>{{end}}{{define "compare"}}{{template "head"}}<header><strong>AirgapProof</strong><a href="/">Run history</a></header><main><h1>Release comparison</h1><p>Baseline <code>{{.Base}}</code> to <code>{{.Head}}</code>.</p><p>Same profile: {{.SameProfile}}. Different profiles can change test coverage.</p><table><tr><th scope="col">Check</th><th scope="col">Before</th><th scope="col">After</th></tr>{{range .Changes}}<tr><td>{{.Name}}</td><td>{{.Before}}</td><td>{{.After}}</td></tr>{{else}}<tr><td colspan="3">No readiness or workflow outcome changes.</td></tr>{{end}}</table><h2>Added findings</h2><ul>{{range .AddedFindings}}<li><code>{{.}}</code></li>{{else}}<li>None</li>{{end}}</ul><h2>Resolved findings</h2><ul>{{range .ResolvedFindings}}<li><code>{{.}}</code></li>{{else}}<li>None</li>{{end}}</ul></main></html>{{end}}`))
