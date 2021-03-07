const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const validator = require('express-validator');
const app = express();
const helmet = require('helmet');
const bodyParser = require('body-parser');
const cookie = require('cookie');
const session = require('express-session');
const https = require('https');
const Datastore = require('nedb');



app.use(bodyParser.json());
app.disable('x-powered-by');
app.use(helmet());

let users = new Datastore({ filename: 'db/users.db', autoload: true });
let messages = new Datastore({
	filename: path.join(__dirname, 'db', 'messages.db'),
	autoload: true,
	timestampData: true
});

let Message = function(content, username) {
	this.content = content;
	this.username = username;
	this.upvote = 0;
	this.downvote = 0;
};


app.use(
	session({
		secret: 's3Cur3-s3ssion',
		resave: false,
		saveUninitialized: true,
		httpOnly: true,
		secure: true,
		sameSite: true
	})
);

function generateSalt() {
	return crypto.randomBytes(16).toString('base64');
}

function generateHash(password, salt) {
	let hash = crypto.createHmac('sha512', salt);
	hash.update(password);
	return hash.digest('base64');
}

app.use(function(req, res, next) {
	let username = req.session.username ? req.session.username : '';
	res.setHeader(
		'Set-Cookie',
		cookie.serialize('username', username, {
			path: '/',
			maxAge: 60 * 60 * 24 * 7, // 1 week in number of seconds,
			secure: true,
			sameSite: true
		})
	);
	next();
});

app.use(express.static('static'));

app.use(function(req, res, next) {
	console.log('HTTP request', req.method, req.url, req.body);
	next();
});

let isAuthenticated = function(req, res, next) {
	if (!req.session.username) return res.status(401).end('access denied');
	next();
};

// curl -H "Content-Type: application/json" -X POST -d '{"username":"alice","password":"alice"}' -c cookie.txt localhost:3000/signup/
app.post(
	'/signup/',
	validator.body('username').isAlphanumeric().withMessage('Invalid username is given'),
	validator.body('password').isStrongPassword().withMessage('A weak password is provided'),
	function(req, res, next) {
		const errors = validator.validationResult(req);
		if (!errors.isEmpty()) {
			let messages = [];
			errors.array().forEach((error) => {
				messages.push(error.msg);
			});
			return res.status(400).json({ errors: messages });
		}
		let username = req.body.username;
		let password = req.body.password;
		users.findOne({ _id: username }, function(err, user) {
			if (err) return res.status(500).end(err);
			if (user) return res.status(409).end('username ' + username + ' already exists');
			let salt = generateSalt();
			let hash = generateHash(password, salt);
			users.update({ _id: username }, { _id: username, salt, hash }, { upsert: true }, function(err) {
				if (err) return res.status(500).end(err);
				return res.json('user ' + username + ' signed up');
			});
		});
	}
);

// curl -H "Content-Type: application/json" -X POST -d '{"username":"user","password":"Hello#Wrold293"}' -c cookie.txt -k https://localhost:3000/signin/
app.post(
	'/signin/',
	validator.body('username').isAlphanumeric().withMessage('Invalid username'),
	validator.body('password').isStrongPassword().withMessage('A weak password is provided'),
	function(req, res, next) {
		const errors = validator.validationResult(req);
		if (!errors.isEmpty()) {
			let messages = [];
			errors.array().forEach((error) => {
				messages.push(error.msg);
			});
			return res.status(400).json({ errors: messages });
		}
		let username = req.body.username;
		let password = req.body.password;
		// retrieve user from the database
		users.findOne({ _id: username }, function(err, user) {
			if (err) return res.status(500).end(err);
			if (!user) return res.status(401).end('access denied');
			if (user.hash !== generateHash(password, user.salt)) return res.status(401).end('access denied'); // invalid password
			// start a session
			req.session.username = user._id;
			res.setHeader(
				'Set-Cookie',
				cookie.serialize('username', user._id, {
					path: '/',
					maxAge: 60 * 60 * 24 * 7, // 1 week in number of seconds
					secure: true,
					sameSite: true
				})
			);
			return res.json('user ' + username + ' signed in');
		});
	}
);

// curl -b cookie.txt -c cookie.txt localhost:3000/signout/
app.get('/signout/', function(req, res, next) {
	req.session.destroy();
	res.setHeader(
		'Set-Cookie',
		cookie.serialize('username', '', {
			path: '/',
			maxAge: 60 * 60 * 24 * 7, // 1 week in number of seconds
			secure: true,
			sameSite: true
		})
	);
	res.redirect('/');
});

// curl -b cookie.txt -H "Content-Type: application/json" -X POST -d '{"content":"hello world!"}' -k https://localhost:3000/api/messages/
app.post(
	'/api/messages/',
	isAuthenticated,
	validator.body('content').not().isEmpty().trim().escape().withMessage('Invalid message posted'),
	function(req, res, next) {
		const errors = validator.validationResult(req);
		if (!errors.isEmpty()) return res.status(400).json(req.error.message);
		let message = new Message(req.body.content, req.session.username);
		messages.insert(message, function(err, message) {
			if (err) return res.status(500).end(err);
			return res.json(message);
		});
	}
);

// curl -b cookie.txt localhost:3000/api/messages/
app.get('/api/messages/', function(req, res, next) {
	messages.find({}).sort({ createdAt: -1 }).limit(5).exec(function(err, messages) {
		if (err) return res.status(500).end(err);
		return res.json(messages.reverse());
	});
});

// curl -b cookie.txt -H "Content-Type: application/json" -X PATCH -d '{"action":"upvote"}' localhost:3000/api/messages/a66mKb0o3pnnYig4/
app.patch(
	'/api/messages/:id/',
	isAuthenticated,
	function(req, res, next) {
		if ([ 'upvote', 'downvote' ].indexOf(req.body.action) == -1)
			return res.status(400).end('unknown action' + req.body.action);
		messages.findOne({ _id: req.params.id }, function(err, message) {
			if (err) return res.status(500).end(err);
			if (!message) return res.status(404).end('Message id #' + req.params.id + ' does not exists');
			let update = {};
			message[req.body.action] += 1;
			update[req.body.action] = 1;
			messages.update({ _id: message._id }, { $inc: update }, { multi: false }, function(err, num) {
				res.json(message);
			});
		});
	}
);

// curl -b cookie.txt -X DELETE -k https://localhost:3000/api/messages/a66mKb0o3pnnYig4/
app.delete(
	'/api/messages/:id/',
	isAuthenticated,
	function(req, res) {
		messages.findOne({ _id: req.params.id }, function(err, message) {
			if (err) return res.status(500).end(err);
			if (!message) return res.status(404).end('Message id #' + req.params.id + ' does not exists');
			if (message.username !== req.session.username) return res.status(403).end('forbidden');
			messages.remove({ _id: message._id }, { multi: false }, function(err, num) {
				res.json(message);
			});
		});
	}
);


const PORT = 3000;

let privateKey = fs.readFileSync('server.key');
let certificate = fs.readFileSync('server.crt');
let config = {
	key: privateKey,
	cert: certificate
};

https.createServer(config, app).listen(PORT, function(err) {
	if (err) console.log(err);
	else console.log('HTTPS server on https://localhost:%s', PORT);
});
