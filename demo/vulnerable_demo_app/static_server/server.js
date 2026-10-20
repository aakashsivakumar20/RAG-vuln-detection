const express = require("express");
const { exec, execFile } = require("child_process");
const db = require("./db");

const app = express();

function searchUsers(req, res) {
  const term = req.query.q;
  const sql = "SELECT id, name FROM users WHERE name LIKE '%" + term + "%'";
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).send("error");
    res.json(rows);
  });
}

function searchUsersSafe(req, res) {
  const term = req.query.q;
  db.query("SELECT id, name FROM users WHERE name LIKE ?", ["%" + term + "%"], (err, rows) => {
    if (err) return res.status(500).send("error");
    res.json(rows);
  });
}

function lookupDns(req, res) {
  const host = req.query.host;
  exec("nslookup " + host, (err, stdout) => {
    res.send(stdout);
  });
}

function lookupDnsSafe(req, res) {
  const host = String(req.query.host);
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) return res.status(400).send("bad host");
  execFile("nslookup", [host], (err, stdout) => {
    res.send(stdout);
  });
}

function profilePage(req, res) {
  const nickname = req.query.nick;
  res.send("<html><body><h2>Profile of " + nickname + "</h2></body></html>");
}

function profilePageSafe(req, res) {
  const nickname = String(req.query.nick).replace(/[&<>"']/g, (c) => "&#" + c.charCodeAt(0) + ";");
  res.send("<html><body><h2>Profile of " + nickname + "</h2></body></html>");
}

function goTo(req, res) {
  res.redirect(req.query.url);
}

function evalFilter(req, res) {
  const rule = req.body.rule;
  const result = eval("(" + rule + ")");
  res.json({ result });
}

app.get("/users", searchUsers);
app.get("/dns", lookupDns);
app.get("/profile", profilePage);
app.get("/go", goTo);
app.post("/filter", evalFilter);
module.exports = app;
