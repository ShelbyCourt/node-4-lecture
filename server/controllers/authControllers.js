const bcrypt = require('bcryptjs')

module.exports = {
  register: async (req, res) => {
    const { email, password } = req.body
    const db = req.app.get('db')

    // db.get_user_by_email(email).then(user =>......)

    //Check if user already exists
    const existingUser = await db.get_user_by_email(email)

    if (existingUser[0]) {
      return res.status(409).send('User already exists')
    }

    //If they do not exist we can carry on

    const salt = bcrypt.genSaltSync(10)

    const hash = bcrypt.hashSync(password, salt)

    //Create new user
    const newUser = await db.create_user([email, hash])

    //Set user on session
    req.session.user = newUser[0]

    //Send back new user
    res.status(200).send(req.session.user)
  },
  login: async (req, res) => {
    const { email, password } = req.body
    const db = req.app.get('db')

    //Make sure user exists
    const existingUser = await db.get_user_by_email(email)

    if (!existingUser[0]) {
      return res.status(404).send('User does not exist')
    }

    //If they do exist, we need to authenticate them
    const authenticated = bcrypt.compareSync(password, existingUser[0].hash)

    //If password does not match
    if (!authenticated) {
      return res.status(403).send('Incorrect password')
    }

    delete existingUser[0].hash

    req.session.user = existingUser[0]

    res.status(200).send(req.session.user)
  },
  logout: (req, res) => {},
}
