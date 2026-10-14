const express = require('express');
const cors = require('cors');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const app = express();
app.use(cors({ origin: '*', credentials: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: false },
}));
app.post('/login', (req, res) => {
  const user = jwt.verify(req.body.token, process.env.JWT_SECRET);
  eval(req.body.script);
  res.json(user);
});
app.listen(3000);
