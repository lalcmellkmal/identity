var bcrypt = require('bcrypt'),
    connect = require('connect'),
    fs = require('fs'),
    template = require('./json-template'),
    RedisStore = require('connect-redis')(connect),
    parseURL = require('url').parse;

// disable uploads
delete connect.bodyParser.parse['multipart/form-data'];

var store = new RedisStore;

var opts = {meta: '{{}}', undefined_str: ''};
var indexTemplate = new template.Template(fs.readFileSync('index.html', 'UTF-8'), opts);
var joinTemplate = new template.Template(fs.readFileSync('join.html', 'UTF-8'), opts);
var welcomeTemplate = new template.Template(fs.readFileSync('welcome.html', 'UTF-8'), opts);
var escape = connect.utils.escape;

var headers = {
	'Content-Type': 'text-html; charset=UTF-8',
	'Expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
	'Cache-Control': 'no-cache',
};

function render(resp, template, context) {
	template.render(context, function (frag) { resp.write(frag); });
}

var server = connect.createServer(
	connect.cookieParser(),
	connect.session({store: store, secret: 'fgsfds'}),
	connect.bodyParser(),
	connect.csrf(),
	//connect.static(__dirname + '/www')
	function (req, resp, next) {
		var url = parseURL(req.url, true);
		if (req.method == 'GET') {
			if (req.session.auth) {
				var name = req.session.auth.name;
				if (url.pathname == '/welcome/') {
					getMembers(function (err, members) {
						if (err) {
							console.error(err);
							members = ['<error>'];
						}
						var info = {name: req.session.auth.name, csrf: req.session._csrf, members: members.join(', ')};
						resp.writeHead(200, headers);
						render(resp, welcomeTemplate, info);
						resp.end();
					});
					return;
				}
				else if (url.pathname == '/') {
					resp.writeHead(303, {Location: 'welcome/'});
					resp.end();
					return;
				}
			}
			else {
				var lastName = url.query.name;
				var info = {csrf: req.session._csrf};
				if (url.pathname == '/') {
					if (lastName) {
						info.msg = 'Invalid login.';
						info.name = lastName;
						info.pass = true;
					}
					resp.writeHead(200, headers);
					render(resp, indexTemplate, info);
					resp.end();
					return;
				}
				else if (url.pathname == '/join/' && url.query.invite) {
					info.invite = url.query.invite;
					resp.writeHead(200, headers);
					render(resp, joinTemplate, info);
					resp.end();
					return;
				}
			}
		}
		else if (req.method == 'POST') {
			var name = req.body.name, pass = req.body.pass;
			if (url.pathname == '/join/') {
				if (pass !== req.body.again)
					return resp.end('Passwords do not match.');
				createLogin(name, pass, req.body.invite, function (err, id) {
					if (err)
						return resp.end(err);
					req.session.auth = {id: id, name: name};
					resp.writeHead(303, {Location: '../welcome/'});
					resp.end();
				});
				return;
			}
			else if (url.pathname == '/login/') {
				checkLogin(name, pass, function (err, login) {
					if (err)
						return resp.end(err);
					var dest;
					if (login) {
						// should we regenerate here?
						req.session.auth = login;
						dest = '../welcome/';
					}
					else {
						dest = '../?name=' + encodeURIComponent(req.body.name);
					}
					resp.writeHead(303, {Location: dest});
					resp.end();
				});
				return;
			}
			else if (url.pathname == '/logout/') {
				req.session.destroy(function (err) {
					if (err) {
						resp.writeHead(500);
						resp.end("Couldn't log out.");
						console.error(err);
					}
					else {
						resp.writeHead(303, {Location: '..'});
						resp.end();
					}
				});
				return;
			}
		}
		next();
	}
);

function checkLogin(name, pass, cb) {
	var r = store.client;
	id <- r.hget('identity:names', name);
	if (!id)
		return false;
	id = parseInt(id, 10);
	hash <- r.hget('identity:passes', id);
	if (!hash) {
		console.warn("Password missing for user " + name);
		return false;
	}
	res <- bcrypt.compare(pass, hash);
	return res ? {id: id, name: name} : false;
}

function createLogin(name, pass, token, cb) {
	var r = store.client;
	if (!name.match(/^[\w '\-]{3,30}$/))
		throw "Invalid name.";
	if (!pass || pass == name)
		throw "Bad password.";
	if (!token)
		throw "Invalid invitation.";

	var invite = 'identity:invite:' + token;
	var redeem = 'identity:redeem:' + token;

	_ <- r.watch(invite, redeem);

	invited <- r.exists(invite);
	if (!invited)
		throw "Invalid invitation.";
	redeemed <- r.exists(redeem);
	if (redeemed)
		throw "Invitation already redeemed.";

	salt <- bcrypt.genSalt(10);
	hash <- bcrypt.hash(pass, salt);
	id <- r.incr('identity:ctr');
	id = parseInt(id, 10);
	if (!id)
		throw "Got invalid ID?!";

	var m = r.multi();
	m.hsetnx('identity:names', name, id);
	m.setnx(redeem, id);
	results <- m.exec();
	if (!results)
		throw "Conflict occurred. Try again.";
	delete m;

	var newName = results[0], redeemed = results[1];
	if (!newName && !redeemed) {
		throw "User already exists.";
	}
	else if (!newName) {
		_ <- r.del(redeem);
		throw "User already exists.";
	}
	else if (!redeemed) {
		_ <- r.hdel('identity:names', name);
		throw "Invitation already redeemed.";
	}

	newPass <- r.hset('identity:passes', id, hash);
	if (!newPass)
		console.warn("Old password overwritten?!");
	return id;
}

function getMembers(cb) {
	var r = store.client;
	members <- r.hkeys('identity:names');
	return shuffle(members);
}

function shuffle(array) {
    var tmp, current, top = array.length;

    if(top) while(--top) {
        current = Math.floor(Math.random() * (top + 1));
        tmp = array[current];
        array[current] = array[top];
        array[top] = tmp;
    }

    return array;
}

server.listen(8000);
