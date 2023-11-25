const jwt = require('jsonwebtoken');
const { scryptSync, randomBytes } = require('node:crypto');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const sql = new sqlite3.Database(path.join(__dirname, 'secrets.sqlite'), (err) => {
    if (err) {
        // Cannot open database
        console.error(err.message)
        throw err
    } else {
        console.log('Connected to the SQLite database.')
        sql.run(`CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                secret TEXT NOT NULL DEFAULT (1234)
                )`, err => {
            //console.log("err: " + JSON.stringify(err))
        });
    }
});

const secret = 'RANDOM_TOKEN_SECRET';

function getSecret(req, res, next) {
    sql.each('SELECT secret FROM secrets WHERE id=? LIMIT 1', [req.userId], (err, row) => {
        if (!err) {
            res.status(200).send(row.secret);
        } else {
            res.sendStatus(500);
        }
    })
}

function setSecret(req, res, next) {
    if (req.body.flag) {
        sql.run('UPDATE secrets SET secret = ? WHERE id = ?', [req.body.flag, req.userId], err => {
            if (!err) {
                res.sendStatus(204);
            } else {
                res.sendStatus(500);
            }
        })
    }
}

function testAuth(req, res, next) {
    try {
        req.userId = jwt.verify(req.headers.my_token, secret).userId;
        next();
    } catch {
        res.sendStatus(403);
    }
}

function login(req, res) {
    if (req.body.mail && req.body.pass) {
        sql.each('SELECT * FROM secrets WHERE email = ? LIMIT 1', [req.body.mail], (err, row) => {
            if (!err) {
                const passEnc = scryptSync(req.body.pass, row.salt, 64).toString('hex');
                if (passEnc === row.password) {
                    const token = jwt.sign({ userId: row.id }, secret, { expiresIn: "10m" });
                    res.status(200).json({ token });
                    return;
                }
            }
            res.sendStatus(403);
        })
    } else {
        res.sendStatus(403);
    }
}

function register(req, res, next) {
    if (req.body.mail && req.body.pass) {
        const salt = randomBytes(32).toString('hex');
        const passEnc = scryptSync(req.body.pass, salt, 64).toString('hex');
        sql.run('INSERT INTO secrets (email, password, salt) VALUES (?,?,?)', [req.body.mail, passEnc, salt], err => {
            if (!err) {
                res.sendStatus(204);
            } else {
                res.sendStatus(500);
            }
        })
    } else {
        res.sendStatus(400);
    }
}

module.exports = {
    testAuth, login, getSecret, setSecret, register
};