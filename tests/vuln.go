package main

import (
    "crypto/rand"
    "crypto/tls"
    "crypto/md5"
    "database/sql"
    "fmt"
    "log"
    "math/rand" // bad RNG
    "net/http"
    "os"
    "os/exec"

    _ "github.com/go-sql-driver/mysql"
)

func main() {
    // Hard-coded credentials
    dbUser := "admin"
    dbPass := "supersecret"

    // Database connection (SQL Injection risk)
    userInput := os.Getenv("USER_ID")
    query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userInput)

    db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(localhost:3306)/mydb", dbUser, dbPass))
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    rows, err := db.Query(query)
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()

    for rows.Next() {
        var username string
        if err := rows.Scan(&username); err != nil {
            log.Fatal(err)
        }
        fmt.Println("User:", username)
    }

    // Insecure TLS config
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    resp, err := client.Get("https://example.com")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    // Weak random number generation
    secretCode := rand.Intn(1000000) // insecure
    fmt.Println("Random code:", secretCode)

    // Weak hashing
    data := []byte("sensitive_data")
    hash := md5.Sum(data)
    fmt.Printf("MD5 hash: %x\n", hash)

    // Command injection risk
    filename := os.Getenv("FILENAME")
    out, err := exec.Command("ls", "-l", filename).CombinedOutput()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(out))
}
