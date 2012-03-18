var bcrypt = require('bcrypt'),
    connect = require('connect'),
    fs = require('fs'),
    template = require('./json-template'),
    RedisStore = require('connect-redis')(connect),
    parseURL = require('url').parse;

var SECRET = 'fgsfds';

var store = new RedisStore;

var opts = {meta: '{{}}', undefined_str: ''};
var indexTemplate = new template.Template(fs.readFileSync('index.html', 'UTF-8'), opts);
var joinTemplate = new template.Template(fs.readFileSync('join.html', 'UTF-8'), opts);
var welcomeTemplate = new template.Template(fs.readFileSync('welcome.html', 'UTF-8'), opts);
var escape = connect.utils.escape;

var headers = {
	'Content-Type': 'text-html; charset=UTF-8',
	'Expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
	'Cache-Control': 'no-cache, no-store',
};

var NAME_REGEXP = /^[\w '\-]{3,30}$/;

function render(resp, template, context) {
	template.render(context, function (frag) { resp.write(frag); });
}

var server = connect()
	.use(connect.cookieParser(SECRET))
	.use(connect.session({store: store, secret: SECRET}))
	.use(connect.bodyParser())
	.use(connect.csrf());

var ROUTER = {get: [], post: []};

server.use(function (req, resp, next) {
	var routes = ROUTER[req.method.toLowerCase()];
	if (!routes)
		return next();
	var url = parseURL(req.url, true);
	tryRoutes.call({req: req, resp: resp, next: next, url: url, routes: routes}, 0);
});

function tryRoutes(i) {
	var routes = this.routes, url = this.url, req = this.req;
	for (; i < routes.length; i++) {
		var route = routes[i];
		if (route.path !== url.pathname)
			continue;

		if (route.noAuth || req.session.auth) {
			req.url = url;
			var next = tryRoutes.bind(this, i + 1);
			route.func(req, this.resp, next);
			return;
		}
	}
	this.next();
}

function routeGet(path, opts, func) {
	if (!func)
		opts = {func: opts};
	else
		opts.func = func;
	opts.path = path;
	ROUTER.get.push(opts);
}

function routePost(path, opts, func) {
	if (!func)
		opts = {func: opts};
	else
		opts.func = func;
	opts.path = path;
	ROUTER.post.push(opts);
}

routeGet('/welcome/', function (req, resp) {
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
});

routeGet('/', function (req, resp) {
	resp.writeHead(303, {Location: 'welcome/'});
	resp.end();
});

routeGet('/', {noAuth: true}, function (req, resp) {
	var lastName = req.url.query.name;
	var info = {csrf: req.session._csrf};
	if (lastName) {
		info.msg = 'Invalid login.';
		info.name = lastName;
		info.pass = true;
	}
	resp.writeHead(200, headers);
	render(resp, indexTemplate, info);
	resp.end();
});

routeGet('/join/', {noAuth: true}, function (req, resp, next) {
	if (!req.url.query.invite)
		return next();
	var info = {csrf: req.session._csrf};
	info.invite = req.url.query.invite;
	resp.writeHead(200, headers);
	render(resp, joinTemplate, info);
	resp.end();
});

routePost('/join/', {noAuth: true}, function (req, resp) {
	var name = req.body.name, pass = req.body.pass;
	if (pass !== req.body.again)
		return resp.end('Passwords do not match.');
	createLogin(name, pass, req.body.invite, function (err, id) {
		if (err)
			return resp.end(err);
		req.session.auth = {id: id, name: name};
		resp.writeHead(303, {Location: '../welcome/'});
		resp.end();
	});
});

routePost('/login/', {noAuth: true}, function (req, resp) {
	var name = req.body.name, pass = req.body.pass;
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
			dest = '../?name=' + encodeURIComponent(name);
		}
		resp.writeHead(303, {Location: dest});
		resp.end();
	});
});

routePost('/logout/', function (req, resp) {
	req.session.destroy(function (err) {
		if (err) {
			resp.writeHead(500);
			resp.end("Couldn't log out.");
			console.error(err);
			return;
		}
		resp.writeHead(303, {Location: '..'});
		resp.end();
	});
});

function loginAttemptDelay(tries) {
	return 50 * Math.pow(2, parseInt(tries, 10) || 0);
}

function checkLogin(name, pass, cb) {
	if (!name.match(NAME_REGEXP))
		return false;

	var r = store.client;

	var ip = '127.0.0.1'; // XXX
	tries <- r.get('identity:tries:' + ip);
	var delay = loginAttemptDelay(tries);

	// acquire lock for this login attempt
	var lockKey = 'identity:try:' + ip;
	var now = new Date().getTime();
	acquired <- r.setnx(lockKey, now + delay + 1000);
	if (acquired) {
		_ <- r.expire(lockKey, now + delay + 60000);
		res <- _delayLoginAttempt(name, pass, ip);
		return res;
	}

	// didn't obtain, check if expired
	expiry <- r.get(lockKey);
	expiry = parseInt(expiry, 10);
	var now = new Date().getTime();
	if (!expiry || expiry >= now)
		return false; // just have them retry later

	// lock is expired, try to reset
	old <- r.getset(lockKey, now + delay + 1000);
	old = parseInt(old, 10);
	if (!old || old >= now)
		return false; // retry later
	// we obtained the refreshed lock
	_ <- r.expire(lockKey, now + delay + 60000);
	_delayLoginAttempt(name, pass, ip, cb);
}

function _delayLoginAttempt(name, pass, ip, cb) {
	_doLoginAttempt(name, pass, function (err, result) {
		if (err || !result) {
			if (err)
				console.error("During login attempt:", err);
			var r = store.client;
			r.incr('identity:tries:' + ip, function (err, tries) {
				if (err)
					throw err; // catastrophic
				setTimeout(cb.bind(null, null, false), loginAttemptDelay(tries));
			});
		}
		else
			cb(null, result);
	});
}

function _doLoginAttempt(name, pass, cb) {
	var r = store.client;
	id <- r.hget('identity:names', name);
	if (!id)
		return false;
	id = parseInt(id, 10);
	hash <- r.hget('identity:passes', id);
	if (!hash)
		throw "Password missing for user " + name;
	res <- bcrypt.compare(pass, hash);
	return res ? {id: id, name: name} : false;
}

function createLogin(name, pass, token, cb) {
	var r = store.client;
	if (!name.match(NAME_REGEXP))
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
