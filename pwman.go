package main

import (
  "crypto/sha256"
  "encoding/hex"
  "fmt"
  "io/ioutil"
  "os"
)

// a map to store username-password pairs
var passwords = make(map[string]string)

func addPassword(username, password string) {
  // hash the password using SHA-256
  hashedPassword := sha256.Sum256([]byte(password))

  // store the hashed password in the map
  passwords[username] = hex.EncodeToString(hashedPassword[:])
}

func checkPassword(username, password string) bool {
  // check if the username is in the map
  if _, ok := passwords[username]; !ok {
    return false
  }

  // hash the password using SHA-256
  hashedPassword := sha256.Sum256([]byte(password))

  // check if the stored password matches the hashed password
  return passwords[username] == hex.EncodeToString(hashedPassword[:])
}

func copyPassword(username string) bool {
  // check if the username is in the map
  if _, ok := passwords[username]; !ok {
    return false
  }

  // copy the password to the clipboard
  err := ioutil.WriteFile("/dev/clipboard", []byte(passwords[username]), os.ModeAppend)
  if err != nil {
    fmt.Println(err)
    return false
  }

  return true
}

func main() {
  // add a few username-password pairs to the password manager
  addPassword("john", "mysecretpassword")
  addPassword("jane", "mysecretsauce")

  // check if the password is correct for a given username
  fmt.Println(checkPassword("john", "mysecretpassword")) // true
  fmt.Println(checkPassword("john", "wrongpassword"))    // false

  // copy the password for a given username to the clipboard
  fmt.Println(copyPassword("john")) // true
}


/*    add <username> <password>: adds a new username-password pair to the password manager.
    check <username> <password>: checks if a password is correct for a given username.
    copy <username>: copies the password for a given username to the clipboard without displaying it.
    list: lists all the username-password pairs in the password manager.
    remove <username>: removes a username-password pair from the password manager. 
*/