package database

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

// Open creates (or opens) vault.db and executes *.sql files in /migrations.
// args : path to the .db file
func Open(dbPath string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite", dbPath+
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	// very small migration runner
	filepath.WalkDir("migrations", func(p string, d fs.DirEntry, _ error) error {
		if d.IsDir() || filepath.Ext(p) != ".sql" {
			return nil
		}
		sql, _ := os.ReadFile(p)
		_, _ = db.Exec(string(sql))
		return nil
	})
	return db, nil
}
