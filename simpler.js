const express = require('express'),
      app = express(),
      basicAuth = require('express-basic-auth'),
      path = require('path'),
      crypto = require('crypto'),
      PORT = process.argv[2] || 2929,
      SPECIAL_CHAR = '~!@#$%^&*';

let keys = {};

function reverse(s) {
  return s.split('').reverse().join('');
}

function shorten(word, length) {
  length = parseInt(process.argv[3]) || length;
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

// get a key via the basic auth password
function basicAuthHandler(username, password) {
  keys[username] = password; 
  return true; // accept any password
}

app.use('/password', basicAuth({ authorizer: basicAuthHandler, challenge: true }));
app.use('/password', express.urlencoded({ extended: true }));
app.use('/password', express.static(path.join('web', 'password')));
app.post('/password', function (req, res) {
  let error = null,
      key = keys[req.auth.user],
      pass = null,
      word = req.body.word;

  delete keys[req.auth.user];

  if (key && word && word.length > 0) {
    pass = crypto.createHmac('sha256', key)
                 .update(word)
                 .digest('base64')
                 .replace(/[^\w]/g, '');
  } else {
    error = error || 'missing ' + (!key ? 'key' : 'word');
  } 

  if (pass) {
    pass = shorten(reverse(special(special(pass))), key.length + word.length);
  } else {
    error = error || 'missing password';
  }

  res.send(error ? error : pass);
});

app.use('/', express.static('web'));

app.listen(PORT);
