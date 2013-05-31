var common       = require('./../../common'),
    config       = common.config,
    logger       = common.logger.prefix('[push]'),
    server       = require('./server'),
    outside      = require('outside'),
    needle       = require('needle'),
    createHash   = require('crypto').createHash,
    Emitter      = require('events').EventEmitter;

var device_key,
    mapped_port,
    upnp_desc    = 'Prey Anti-Theft',
    port_start   = 30300,
    max_attempts = 30;

var chars = 'abcdefghijklmnopqrstuvwxyz0123456789';

var md5 = function(str){
  return createHash('md5').update(str).digest('hex');
};

var map_port = function(port, attempt, cb){
  var opts = {
    external: port,
    internal: port,
    name: upnp_desc
  }

  logger.info('Attempting to map external port ' + port);
  outside.map(opts, function(err, resp){
    if (!err) return cb(null, port);

    if (attempt < max_attempts && err.message.match('Already mapped'))
      map_port(port + 1, attempt + 1, cb); // try one above
    else
      cb(err);
  })
};

var send_notification_id = function(port, cb){
  var host = config.get('protocol') + '://' + config.get('host'),
      url  = host + '/devices/' + device_key + '/data';

  outside.ip(function(err, ip){
    if (err) return cb(err);

    var str = new Buffer(ip + ':' + port).toString('base64');
    var data = { notification_id: str };

    logger.info('Updating notification ID at ' + url);
    needle.post(url, data, function(err, resp, body){
      cb(resp && resp.responseCode < 300);
    });

  });

};

var find_mapping = function(cb){

  var found;

  logger.info('Checking for existing mappings...');
  outside.mine(function(err, list){
    if (err) return cb(err);

    list.forEach(function(mapping){
      if (mapping.NewPortMappingDescription.match(upnp_desc))
        found = mapping;
    });

    cb(null, found);
  })

};

var unload = function(err){
  if (err) logger.error('Unloading due to error: ' + err.message);

  server.stop();
  if (mapped_port)
    outside.unmap({ external: mapped_port });
};

// called from load method once we have a mapped port
var mapped = function(err, port){
  if (err) return cb(err);

  mapped_port = port;
  var emitter = new Emitter();

  logger.info('Port ' + port + ' mapped. Starting push handler.');
  server.listen(port, function(err, request){
    if (err) return cb(err);

    request.on('data', function(data){
      if (data.command && data.target)
        emitter.emit(data.command, data.target, data.options);
    });

    send_notification_id(port, function(success){
      if (!success)
        return unload(new Error('Unable to send notification ID.'));

      cb(emitter);
    });

  });

};


exports.load = function(opts, cb){

  var port;
  device_key = config.get('device_key');

  if (!device_key || device_key == '')
    return cb(new Error('Device key not present.'));

  find_mapping(function(err, mapping){
    if (err) return cb(err);

    if (mapping) {
      logger.info('Found existing mapping! Using port ' + mapping.NewExternalPort);
      mapped(null, mapping.NewExternalPort);
    } else { // not mapped or mapped to someone else
      var port = port_start + chars.split('').indexOf(device_key[0]);
      map_port(port, 1, mapped)
    }

  });

}

exports.unload = function(cb){
  unload();
  cb && cb();
}