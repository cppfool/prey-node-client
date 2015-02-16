var needle  = require('needle'),
    https   = require('https'),
    keys    = require('./keys'),
    logger  = require('./logger'),
    common  = require('./../../../common'),
    version = '2';

var defaults = {
  client     : needle,
  protocol   : 'https',
  host       : 'solid.preyproject.com',
  user_agent : 'Prey Client API v' + version,
  timeout    : 90 * 1000
}

https.globalAgent.options.secureProtocol = 'TLSv1_method';

var api_root = '/api/v2';
var max_attempts = 3;

var is_network_down = function(err) {
  var codes = ['ENETDOWN', 'ENETUNREACH', 'EADDRINFO', 'ENOTFOUND'];
  return codes.indexOf(err.code) !== -1;
}

var is_server_down = function(err) {
  var codes = ['ETIMEDOUT', 'ECONNRESET', 'ECONNREFUSED'];
  return codes.indexOf(err.code) !== -1;
}

var is_temporary_error = function(err, resp) {
  var retry = false;

  if (err)
    retry = (is_server_down(err) || err.message.match('socket hang up'));
  else
    retry = (resp.statusCode == 502 || resp.statusCode == 503);

  return retry;
}

var send = function(attempt, method, path, data, options, cb) {
  if (!defaults.client)
    return cb(new Error('No HTTP client set!'))

  var opts = options || {};
  opts.timeout    = opts.timeout    || defaults.timeout;
  opts.user_agent = opts.user_agent || defaults.user_agent;

  if (!opts.username) {
    opts.username = keys.get().api;
    opts.password = 'x';
  }

  // Either http://my.proxy.com:1234 or http://10.10.1.2:1234
  proxy_regex = /^(https?:\/\/)?(([\da-z\.-]+)\.([a-z\.]{2,6})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))([\/\w \.-]*)*\:[0-9]{1,5}$/;
  try_proxy = common.config && common.config.get('try_proxy');
  if (String(try_proxy).match(proxy_regex)) {
    opts.proxy = try_proxy;
    // We provide auth header, since needle will use the credentials we provide to
    // create a Proxy-Authorization one.
    opts.headers = {};
    opts.headers.Authorization = basic_auth(opts.username, opts.password);
    opts.username = common.config.get('proxy_username');
    opts.password = common.config.get('proxy_password');
    logger.debug("Using proxy: " + try_proxy);
  }

  var base  = defaults.protocol + '://' + defaults.host,
      url   = base + api_root + path,
      start = new Date();

  logger.debug('Sending ' + method + ' request #' + attempt + ' to ' + base);
  // console.log(opts);

  defaults.client.request(method, url, data, opts, function(err, resp, body) {
    var seconds = (new Date() - start) / 1000;
    logger.debug('Attempt #' + attempt + ' took ' + seconds + ' seconds.');

    if (err && is_network_down(err)) {

      err.message = 'Network seems to be down. Check your connection and try again.';
      return cb(err);

    } else if (is_temporary_error(err, resp)) {

      if (attempt < max_attempts) { // retry the request
        logger.debug('Temporary network error. Retrying...');
        return setTimeout(function() {
          send(attempt + 1, method, path, data, options, cb);
        }, 3000);
      } else if (err) { // maxed out all attempts. tell user to retry in a sec.
        err.message = err.message + ' - Please try again in a minute.';
      }

    }

    cb(err, resp, body);
  });
}

var basic_auth = function(user, pass) {
  var str  = typeof pass == 'undefined' ? user : [user, pass].join(':');
  return 'Basic ' + new Buffer(str).toString('base64');
}

exports.get = function(path, opts, cb) {
  send(1, 'GET', path, null, opts, cb);
}

exports.post = function(path, data, opts, cb) {
  send(1, 'POST', path, data, opts, cb);
}

exports.delete = function(path, opts, cb) {
  send(1, 'DELETE', path, null, opts, cb);
}

exports.use = function(obj) {
  for (var key in obj) {
    if (defaults.hasOwnProperty(key)) {

      // logger.debug('Setting ' + key + ' to ' + obj[key]);

      if (key == 'protocol' && ['http', 'https'].indexOf(obj[key]) === -1) {
        logger.error('Invalid protocol: ' + obj[key]);
        continue;
      }

      if (!obj[key]) {
        logger.error('Empty API value for key: ' + key);
        continue;
      }

      defaults[key] = obj[key];
    }
  }
  return defaults;
}
