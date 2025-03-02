package config

import (
	"database/sql/driver"
	"log"
	"time"
)

// LoggingDriver wraps a SQL driver to log queries
type LoggingDriver struct {
    parent driver.Driver
}

// Open returns a new connection
func (d *LoggingDriver) Open(name string) (driver.Conn, error) {
    conn, err := d.parent.Open(name)
    if err != nil {
        return nil, err
    }
    return &LoggingConn{conn: conn}, nil
}

// LoggingConn wraps a driver.Conn to log queries
type LoggingConn struct {
    conn driver.Conn
}

// Prepare returns a prepared statement
func (c *LoggingConn) Prepare(query string) (driver.Stmt, error) {
    stmt, err := c.conn.Prepare(query)
    if err != nil {
        return nil, err
    }
    return &LoggingStmt{stmt: stmt, query: query}, nil
}

// Close closes the connection
func (c *LoggingConn) Close() error {
    return c.conn.Close()
}

// Begin starts a transaction
func (c *LoggingConn) Begin() (driver.Tx, error) {
    tx, err := c.conn.Begin()
    if err != nil {
        return nil, err
    }
    log.Println("DB: Transaction started")
    return &LoggingTx{tx: tx}, nil
}

// LoggingStmt wraps a driver.Stmt to log queries
type LoggingStmt struct {
    stmt  driver.Stmt
    query string
}

// Close closes the statement
func (s *LoggingStmt) Close() error {
    return s.stmt.Close()
}

// NumInput returns the number of placeholder parameters
func (s *LoggingStmt) NumInput() int {
    return s.stmt.NumInput()
}

// Exec executes a query
func (s *LoggingStmt) Exec(args []driver.Value) (driver.Result, error) {
    start := time.Now()
    log.Printf("DB EXEC: %s %v", s.query, args)
    
    result, err := s.stmt.Exec(args)
    
    elapsed := time.Since(start)
    log.Printf("DB EXEC completed in %s", elapsed)
    
    if err != nil {
        log.Printf("DB EXEC error: %v", err)
    }
    
    return result, err
}

// Query executes a query
func (s *LoggingStmt) Query(args []driver.Value) (driver.Rows, error) {
    start := time.Now()
    log.Printf("DB QUERY: %s %v", s.query, args)
    
    rows, err := s.stmt.Query(args)
    
    elapsed := time.Since(start)
    log.Printf("DB QUERY completed in %s", elapsed)
    
    if err != nil {
        log.Printf("DB QUERY error: %v", err)
    }
    
    return rows, err
}

// LoggingTx wraps a driver.Tx to log queries
type LoggingTx struct {
    tx driver.Tx
}

// Commit commits the transaction
func (t *LoggingTx) Commit() error {
    err := t.tx.Commit()
    if err != nil {
        log.Println("DB: Transaction commit failed:", err)
    } else {
        log.Println("DB: Transaction committed")
    }
    return err
}

// Rollback rolls back the transaction
func (t *LoggingTx) Rollback() error {
    err := t.tx.Rollback()
    if err != nil {
        log.Println("DB: Transaction rollback failed:", err)
    } else {
        log.Println("DB: Transaction rolled back")
    }
    return err
}