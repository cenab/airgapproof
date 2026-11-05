package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/cenab/airgapproof/internal/report"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ DB *pgxpool.Pool }
type Team struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Policy Policy `json:"policy"`
}
type Run struct {
	ID          string         `json:"id"`
	TeamID      int64          `json:"team_id"`
	Application string         `json:"application"`
	Revision    string         `json:"revision"`
	CreatedAt   time.Time      `json:"created_at"`
	Status      string         `json:"status"`
	GatePassed  bool           `json:"gate_passed"`
	SHA256      string         `json:"sha256"`
	Report      *report.Report `json:"report,omitempty"`
	Decision    Decision       `json:"decision"`
}

func Open(ctx context.Context, url string) (*Store, error) {
	c, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("invalid database connection configuration")
	}
	c.MaxConns = 10
	db, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		return nil, err
	}
	s := &Store{DB: db}
	if err = db.Ping(ctx); err != nil {
		db.Close()
		return nil, errors.New("cannot connect to PostgreSQL")
	}
	_, err = db.Exec(ctx, `CREATE TABLE IF NOT EXISTS ap_teams (id BIGSERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, token_hash BYTEA UNIQUE NOT NULL, policy JSONB NOT NULL); CREATE TABLE IF NOT EXISTS ap_runs (id TEXT NOT NULL, team_id BIGINT NOT NULL REFERENCES ap_teams(id), application TEXT NOT NULL, revision TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, received_at TIMESTAMPTZ NOT NULL DEFAULT now(), status TEXT NOT NULL, gate_passed BOOLEAN NOT NULL, sha256 TEXT NOT NULL, report JSONB NOT NULL, decision JSONB NOT NULL, PRIMARY KEY(team_id,id)); CREATE INDEX IF NOT EXISTS ap_runs_history ON ap_runs(team_id,received_at DESC);`)
	if err != nil {
		db.Close()
		return nil, errors.New("cannot initialize dashboard schema")
	}
	return s, nil
}
func Token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func (s *Store) CreateTeam(ctx context.Context, name string, p Policy) (Team, string, error) {
	if len(name) < 1 || len(name) > 120 {
		return Team{}, "", errors.New("team name must contain 1–120 characters")
	}
	if err := p.Validate(); err != nil {
		return Team{}, "", err
	}
	token := Token()
	hash := sha256.Sum256([]byte(token))
	b, _ := json.Marshal(p)
	var id int64
	err := s.DB.QueryRow(ctx, "INSERT INTO ap_teams(name,token_hash,policy) VALUES($1,$2,$3) RETURNING id", name, hash[:], b).Scan(&id)
	return Team{ID: id, Name: name, Policy: p}, token, err
}
func (s *Store) TeamByToken(ctx context.Context, token string) (Team, error) {
	hash := sha256.Sum256([]byte(token))
	var t Team
	var b []byte
	err := s.DB.QueryRow(ctx, "SELECT id,name,policy FROM ap_teams WHERE token_hash=$1", hash[:]).Scan(&t.ID, &t.Name, &b)
	if err == nil {
		err = json.Unmarshal(b, &t.Policy)
	}
	return t, err
}
func (s *Store) Teams(ctx context.Context) ([]Team, error) {
	rows, err := s.DB.Query(ctx, "SELECT id,name,policy FROM ap_teams ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	teams := []Team{}
	for rows.Next() {
		var t Team
		var b []byte
		if err = rows.Scan(&t.ID, &t.Name, &b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &t.Policy); err != nil {
			return nil, err
		}
		teams = append(teams, t)
	}
	return teams, rows.Err()
}
func (s *Store) SetPolicy(ctx context.Context, id int64, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	b, _ := json.Marshal(p)
	tag, err := s.DB.Exec(ctx, "UPDATE ap_teams SET policy=$1 WHERE id=$2", b, id)
	if err == nil && tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return err
}
func (s *Store) Rotate(ctx context.Context, id int64) (string, error) {
	token := Token()
	hash := sha256.Sum256([]byte(token))
	tag, err := s.DB.Exec(ctx, "UPDATE ap_teams SET token_hash=$1 WHERE id=$2", hash[:], id)
	if err == nil && tag.RowsAffected() != 1 {
		err = pgx.ErrNoRows
	}
	return token, err
}
func (s *Store) AddRun(ctx context.Context, team Team, r *report.Report) (Run, error) {
	if err := r.Validate(); err != nil {
		return Run{}, err
	}
	if r.Signature != nil {
		if err := r.Verify(nil); err != nil {
			return Run{}, err
		}
	}
	b, _ := json.Marshal(r)
	decision := team.Policy.Evaluate(r)
	d, _ := json.Marshal(decision)
	hash := report.Hash(b)
	_, err := s.DB.Exec(ctx, "INSERT INTO ap_runs(id,team_id,application,revision,created_at,status,gate_passed,sha256,report,decision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", r.ID, team.ID, r.Application, r.Revision, r.CreatedAt, r.Status, decision.Passed, hash, b, d)
	return Run{ID: r.ID, TeamID: team.ID, Application: r.Application, Revision: r.Revision, CreatedAt: r.CreatedAt, Status: r.Status, GatePassed: decision.Passed, SHA256: hash, Decision: decision}, err
}
func (s *Store) Runs(ctx context.Context, team int64, app string) ([]Run, error) {
	rows, err := s.DB.Query(ctx, "SELECT id,team_id,application,revision,created_at,status,gate_passed,sha256,decision FROM ap_runs WHERE ($1::bigint=0 OR team_id=$1) AND ($2::text='' OR application=$2) ORDER BY received_at DESC LIMIT 100", team, app)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := []Run{}
	for rows.Next() {
		var r Run
		var b []byte
		if err = rows.Scan(&r.ID, &r.TeamID, &r.Application, &r.Revision, &r.CreatedAt, &r.Status, &r.GatePassed, &r.SHA256, &b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &r.Decision); err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}
	return runs, rows.Err()
}
func (s *Store) Get(ctx context.Context, team int64, id string) (Run, error) {
	var r Run
	var b, d []byte
	err := s.DB.QueryRow(ctx, "SELECT id,team_id,application,revision,created_at,status,gate_passed,sha256,report,decision FROM ap_runs WHERE team_id=$1 AND id=$2", team, id).Scan(&r.ID, &r.TeamID, &r.Application, &r.Revision, &r.CreatedAt, &r.Status, &r.GatePassed, &r.SHA256, &b, &d)
	if err == nil {
		err = json.Unmarshal(b, &r.Report)
	}
	if err == nil {
		err = json.Unmarshal(d, &r.Decision)
	}
	return r, err
}
