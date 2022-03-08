const express = require('express')
const bodyParser = require('body-parser')
const {check, validationResult, body} = require('express-validator')
const app = express()
const port = process.env.PORT || 5000
const cookieParser = require('cookie-parser');
const crypto = require('crypto')
app.use(express.json())
const mysql = require('mysql')
const bcrypt = require('bcrypt')
const session = require('express-session')
let alert = require('alert');
const csrf = require('csurf')

app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}));

app.use(cookieParser('MY SECRET'));
const csrfProtection = csrf(({cookie: true}))
const urlEncodedParser = bodyParser.urlencoded({extended:false})


//protection no-cache en tout temps, ne rien storer car charger l'app n'est pas un probleme
app.use((req,res, next) => {
    res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.header('Expires', '-1');
    res.header('Pragma', 'no-cache');
    res.setHeader('X-Frame-Options', 'sameorigin'); //prevent clickjacking
    next();
})

app.set('view engine', 'ejs')
//mysql
const pool = mysql.createPool({
    connectionLimit : 10,
    host            : 'us-cdbr-east-05.cleardb.net',
    user            : 'be15cc1e26474b',
    password        : '5676dc60',
    database        : 'heroku_221a1e58d37b7fd',
    port: process.env.PORT || 3306,
})


//options pour prévenir certains attaques
let options = {
    maxAge: 1000 * 60 * 15,
    httpOnly: true, //refleted xss attacks
    signed: true //samesite
}


app.get('',  csrfProtection, (req, res) => {
    randomID = crypto.randomUUID()
    cookieName = crypto.randomUUID()
    res.cookie(cookieName, randomID, options, { signed : true });
    res.render('index', {csrfToken: req.csrfToken()});
})

app.get('/register', csrfProtection, (req, res)=> {
    randomID = crypto.randomUUID()
    cookieName = crypto.randomUUID()
    res.cookie(cookieName, randomID, options,{ signed : true });
    res.render('register',  {csrfToken: req.csrfToken()})
})

//check handles xss with express-validator
app.post('/register', urlEncodedParser,
    [
        check('username', 'This username must be 3+ characters long').isAlphanumeric(),
        check('email', 'Email is not valid').isEmail().normalizeEmail(),
        check('password', 'Your password require an uppercase Letter, a special character and a number.').isStrongPassword(),
        check('number', 'You need a valid phone number.').matches(/^[]?[(]?[0-9]{3}[)]?[-\s]?[0-9]{3}[-\s]?[0-9]{4,6}$/im)
    ],
     (req, res)=> {
     const errors = validationResult(req)
        if (!errors.isEmpty()) {
            const alert = errors.array()
            res.render('register', {
                alert
            }, )
        }
        else {
            pool.getConnection(async (err, connection) => {
                if (err) throw err

                let params = req.body;
                const salt = await bcrypt.genSalt();
                params.password = await bcrypt.hash(params.password, salt);

                connection.query('INSERT INTO db_users SET ?', params, (err, rows) => {
                    connection.release();

                    if (!err) {
                        res.render('login')
                    } else {
                        console.log(err)
                    }
                })
            })}
    })

app.get('/login', (req, res) => {
    res.render('login')
})

//check handles xss with express-validator
app.post('/login', urlEncodedParser,     [
    check('username').isAlphanumeric(),
    check('password').isStrongPassword(),
],async (req, res) => {

    const username = req.body.username
    const query=("SELECT password FROM db_users WHERE username = ?");

    pool.getConnection( async (err, connection) => {
        if (err) throw err

        connection.query(query, username, async (err, rows) => {

            if (err) throw err;

            if (rows.length !== 0) {
                const password_hash = rows[0]["password"];
                const verified = await bcrypt.compare(req.body.password, password_hash);
                console.log(verified)
                if (verified) {
                    req.session.loggedin = true;
                    req.session.username = username
                    req.session.username = username
                    res.redirect('/home' )
                }
             else {
                    alert('Invalid username or password') //revoir
                }
            }
        })
    })
    })

app.get('/home', urlEncodedParser, csrfProtection, function(req, res) {
    // If the user is loggedin
    if (req.session.loggedin) {
        res.render('home', {csrfToken: req.csrfToken()})

    } else {
        // Not logged in
        res.redirect('login')
    }
});

app.get('/home/account',  urlEncodedParser, csrfProtection, (req, res) => {
    // If the user is loggedin
    if (req.session.loggedin) {
        res.render('account', {csrfToken: req.csrfToken()})
    } else {
        // Not logged in
        res.redirect('/')
    }
});

app.get("/logout", (req,res) => {
    req.session.loggedin = false;
    res.redirect("/login");
});

app.listen(port, () => console.info(`App listening on port: ${port}`))
