require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive(CONNECTION_STRING).then(db => {
  app.set('db', db);
});

app.post('/auth/signup', async (req, res) => {
  const {email, password} = req.body;
  const db = req.app.get('db');
  const {session} = req;
  const user = await db.check_user_exists([email]);
  user = user[0];
  if(user){
    return res.status(400).send('User already exists')
  }
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  const newUser = await db.create_user([email, hash])
  newUser = newUser[0];
  session.user = {id: newUser.id, email: newUser.email};
  res.status(200).send(session.user);
})

app.post('/auth/login', async (req, res) => {
  const {email, password} = req.body;
  const db = req.app.get('db');
  const {session} = req;
  const user = await db.check_user_exists([email]);
  user = user[0];
  if(!user){
    return res.status(400).send('Incorrect email, please try again')
  }
  const authenticated = bcrypt.compareSync(password, user.user_password);
  if(authenticated){
    session.user = {id: user.id, email: user.email}
    res.status(200).send(session.user);
  } else {
    res.status(401).send('Incorrect email/password');
  }
})

app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.sendStatus(200)
})

app.get('/auth/user', (req, res) => {
  if(req.session.user){
    res.status(200).send(req.session.user)
  } else {
    res.status(401).send('please log in')
  }
})

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
