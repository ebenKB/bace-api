const express = require('express')
const bodyParser = require('body-parser')
const bcrypt = require('bcrypt');
const app = express()
const port = 8080
const cors = require('cors')

// hash password
const saltRounds = 10;

app.use(bodyParser.json())
app.use(cors())

// temporary database
let db = []

app.get('/', (req, res) => {
  res.status(200).json({success: true})
})

app.post('/login', async (req, res) => {
  const data = req.body;
  // check if the user is registered
  const user = await checkUser(data.email, data.password);
  if ( user ) {
    return res.status(200).json({
      message: 'success',
      user
    })
  } else {
    return res.status(404).json({
      message: 'No user found for these credentials.'
    })
  }
});

app.post('/signup',  cors(),(req, res) => {
  const { user } = req.body;
  if (user) {
    // hash user password
    bcrypt.genSalt(saltRounds, async (err, salt) => {
      if(!err) {
        const hashed = await bcrypt.hash(user.password, salt)
        
        // save the new user
        db = [...db, {name: user.name, password: hashed, email: user.email}]
      }
    })
    const { password, ...rest } = user
    res.status(200).json({ message: "user has been created", user: {...rest }})
  } else {
    return res.status(404).json({
      message: 'User not found in request body'
    })
  }
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})

// verify the user's credentials
const checkUser = async (email, password) => {
  const user = db.find((x) => x.email === email);
  if (user) {
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      const { password, ...rest } = user;
      return rest;
    } else return false;
  }
}
