require('dotenv').config()
const express = require('express')
const app = express()
const massive = require('massive')
const session = require('express-session')
const sessionCtrl = require('./controllers/sessionController')
const authCtrl = require('./controllers/authController')
const checkForSession = require('./middlewares/checkForSession')
const { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env

app.use(express.json())
app.use(
  session({
    resave: false,
    saveUninitialized: true,
    secret: SESSION_SECRET,
    cookie: { maxAge: 1000 * 60 * 60 * 24 },
  })
)

app.get('/session', sessionCtrl.checkSession)
app.post('/auth/register', authCtrl.register)
app.post('/auth/login', checkForSession, authCtrl.login)
app.delete('/auth/logout', authCtrl.logout)

massive({
  connectionString: CONNECTION_STRING,
  ssl: { rejectUnauthorized: false },
}).then((dbInstance) => {
  app.set('db', dbInstance)
  console.log(`DB Spun up`)
  app.listen(SERVER_PORT, () =>
    console.log(`Authenticate me cap'n on port ${SERVER_PORT}`)
  )
})
