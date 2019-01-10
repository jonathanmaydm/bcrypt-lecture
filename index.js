const express = require("express");
const app = express();
const bcrypt = require("bcryptjs");
const { json } = require("body-parser");
const massive = require("massive");
const session = require("express-session");

// our authMiddleware function can be added to any route
// that we want to require a user to be logged in to access.
// be sure not to put this on your log in or sign up routes,
// otherwise nobody will be able to log in!
const authMiddleware = (req, res, next) => {
  if (!req.session.user) {
    res.status(401).json({ error: "Please log in" });
  } else {
    next();
  }
};

// we need to accept data from our user in req.body
// so we use json() middleware from body-parser
app.use(json());

// our user information will eventually be saved to the session
app.use(
  session({
    secret: "really safe",
    resave: true,
    saveUninitialized: false
  })
);

massive("CONNECTION_STRING").then(db => app.set("db", db));

app.post("/auth/login", (req, res) => {
  // first we need to find the user in the database based on their username
  // you can use a .sql file in you db folder, or the built in methods
  // from massive. Here we're using a built in method that returns either
  // the one user it finds or null if no user is found.
  req.app
    .get("db")
    .app_user.findOne({ username: req.body.username })
    .then(user => {
      if (!user) {
        // if there's no user found, we need to send back an error
        res.status(401).json({ error: "User not found" });
      } else {
        // otherwise, let's compare the passwords. We only compare the password
        // if we know the user exists, so we don't waste computer power hashing
        // a password for the wrong username

        // req.body.password is the plaintext password the user sent with their
        // log in request.
        // user.password is the hashed password from the database
        bcrypt.compare(req.body.password, user.password).then(result => {
          //result is true if the hashes match or false if they don't
          if (!result) {
            //if they don't match, send back an error
            res.status(401).json({ error: "Incorrect password" });
          } else {
            // if they do match, add the user to the session.
            // Be careful what information you add to the user object on
            // session -- you probably don't want to add all the information
            // from the database to the session.
            req.session.user = { username: user.username, role: user.role };
            // Send a response back to the client to let them know it succeeded
            res.json("ok");
          }
        });
      }
    });
});

// when a user signs up, we need to hash their password
// and then save their username and hash to the database
app.post("/auth/signup", async (req, res) => {
  // remember that let and const are block scoped
  // so they only exist in the block where they're declared
  // if we declare hash inside the try block, it only exists there
  let hash;

  // try/catch blocks are a way to catch errors in async/await code
  // the catch portion is just like the .catch method on a promise
  try {
    // first we hash the password they send us
    hash = await bcrypt.hash(req.body.password, 10);
  } catch (e) {
    // if a problem happens when we try to hash it, send an error back to the server
    // ex. if they didn't send a password at all
    res.status(500).json("Unknown error");
  }

  try {
    // then try to save the username and hash into the database
    await req.app.get("db").app_user.insert({
      username: req.body.username,
      password: hash
    });
  } catch (e) {
    // there might be an error, especially if a user with the same
    // username already exists
    res.status(400).json({ error: "User already exists" });
  }

  // if everything succeeded, add the user to the session
  // and send a response to the client
  req.session.user = { username: req.body.username };
  res.json("ok");
});

// we only want logged in users to be able to access profile
// so we add authMiddleware (defined at the top of the file)
// to check for the user on the session before it can
// continue on to the sensitive information
app.get("/profile", authMiddleware, (req, res) => {
  res.json(req.session.user);
});

// we only want admins to be able to access this route,
// so we can add different middleware to check if the
// logged in user has authorization
app.get(
  "/admin",
  (req, res, next) => {
    if (req.session.user.role !== "admin") {
      res.status(403).json({ error: "Not authorized for this content" });
    } else {
      next();
    }
  },
  (req, res) => {
    /* Really important stuff that only 
    admins can do */
    res.json("ok");
  }
);

app.listen(5050, () => {
  console.log("Listening on 5050");
});
