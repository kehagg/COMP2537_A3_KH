
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");
const mongoSanitize = require('express-mongo-sanitize');
const { emit } = require("process");
const { type } = require("os");
const expireTime = 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

app.use(mongoSanitize(
    //{replaceWith: '%'}
));

// app.use(
//     mongoSanitize({
//       onSanitize: ({ req, key }) => {
//         console.warn(`This request[${key}] is sanitized`);
//       },
//     }),
//   );

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions2`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.get('/', (req, res) => {
    res.render('index', {
        authenticated: req.session.authenticated,
        username: req.session.username
    });
});

function isValidSession(req) {
    return req.session.authenticated;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    } else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    return req.session.user_type == 'admin';
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", { error: "Not authorized - 403." });
        return;
    } else {
        next();
    }
}

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({ username: 1, _id: 1 }).toArray();
    res.render('admin', { users: result });
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    } else {
        var result = {
            username: req.session.username,
            image1: 'duck.gif',
            image2: 'frog.gif',
            image3: 'spongebob.gif'
        };
        res.render('members', result);
    }
});

app.get('/signupSubmit', (req, res) => {
    var missing = req.query.missing;
    res.render('signupSubmit', { missing: missing });
});

app.get('/signup', (req, res) => {
    res.render("signup");
});


app.post('/admin', async (req, res) => {
    console.log(req.body.userName);
    await userCollection.updateOne({ username: req.body.userName }, { $set: { user_type: req.body.userType } });
    if (req.body.userName == req.session.username) {
        req.session.user_type = req.body.userType;
    }
    res.redirect('/admin');
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: " + email);
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/loginSubmit', (req, res) => {
    const missing = req.query.missing;
    res.render('loginSubmit', { missing: missing });
});

app.post('/signup', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (username == '' && email == '' && password == '') {
        console.log("all are empty");
        res.redirect('/signupSubmit?missing=1');
        return;
    } else if (username == '' && email == '') {
        console.log("name and email are empty");
        res.redirect('/signupSubmit?missing=2');
        return;
    } else if (username == '' && password == '') {
        console.log("name and password are empty");
        res.redirect('/signupSubmit?missing=3');
        return;
    } else if (email == '' && password == '') {
        console.log("email and password are empty");
        res.redirect('/signupSubmit?missing=4');
        return;
    } else if (username == '') {
        console.log("name is empty");
        res.redirect('/signupSubmit?missing=5');
        return;
    } else if (email == '') {
        console.log("email is empty");
        res.redirect('/signupSubmit?missing=6');
        return;
    } else if (password == '') {
        console.log("password is empty");
        res.redirect('/signupSubmit?missing=7');
        return;
    }

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().max(40).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, email, password });

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/signup");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    // To add admin user

    // await userCollection.insertOne({
    //     username: username, email: email, password: hashedPassword,
    //     user_type: 'admin'
    // });
    // req.session.user_type = 'admin';
    // console.log("Inserted admin");

    // To add regular user

    await userCollection.insertOne({
        username: username, email: email, password: hashedPassword,
        user_type: 'user'
    });
    req.session.user_type = 'user';
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(40).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, _id: 1, user_type: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/loginSubmit?missing=1");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;
        req.session.user_type = result[0].user_type;
        console.log(result[0].user_type);

        res.redirect('/loggedIn');
        return;
    }
    else {
        console.log("incorrect password");
        res.redirect("/loginSubmit?missing=2");
        return;
    }
});

app.use('/loggedin', sessionValidation);
app.get('/loggedIn', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.redirect('/members');
});


app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 