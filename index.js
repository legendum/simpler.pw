const express = require('express'),
      app = express(),
      basicAuth = require('express-basic-auth'),
      path = require('path'),
      crypto = require('crypto'),
      SPECIAL_CHAR = '~!@#$%^&*',
      MIN_PASSWORD_LENGTH = 30;

let salts = {};

function reverse(s) {
  return s.split('').reverse().join('');
}

function shorten(word) {
  var length = parseInt(process.argv.pop()) || process.env.PASS_SIZE;
  return length > 0 ? word.substr(0, length) : word;
}

function special(s) {
  var code = 0;
  for (var i = 0; i < s.length; i++) {
    code += s.charCodeAt(i);
  }
  var char = SPECIAL_CHAR[ code % SPECIAL_CHAR.length ],
      left = code % s.length;

  return s.substr(0, left) + char + s.substr(left);
}

// get a salt via the basic auth password
function basicAuthHandler(username, password) {
  salts[username] = password; 
  return true;
}

app.use(basicAuth({
  authorizer: basicAuthHandler,
  challenge: true
}));

app.use(express.urlencoded({extended: true}));

app.get('/', function (req, res) {
  res.sendFile(path.join(__dirname + '/index.html'));
});

app.post('/', function (req, res) {
  let error = null,
      salt = salts[req.auth.user],
      pass = null,
      word = req.body.word;

  if (salt && word && word.length > 0) {
    pass = crypto.createHmac('sha256', salt)
                 .update(word)
                 .digest('base64')
                 .replace(/[^\w]/g, '');
  } else {
    error = error || 'missing ' + (!salt ? 'salt' : 'word');
  } 

  if (pass && pass.length >= MIN_PASSWORD_LENGTH) {
    pass = shorten(reverse(special(special(pass))));
  } else {
    error = error || 'password too short';
  }

  res.send(error ? error : pass);
});

app.listen(2929)

// EOF
