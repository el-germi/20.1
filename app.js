const express = require('express');
const path = require('path');
const { testAuth, login, register, getSecret, setSecret } = require('./middleware/auth');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

const log = (req, res, next) => {
    //console.log("body: " + JSON.stringify(req.body));
    //console.log("tokn: " + req.headers.my_token);
    next();
}

app.post('/api/register', log, register)
app.post('/api/login', log, login)
app.get('/api/flag', testAuth, log, getSecret)
app.post('/api/flag', testAuth, log, setSecret)
app.get('/api/quit', log, () => process.exit(0))

module.exports = app;