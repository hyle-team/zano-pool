// Copyright (c)2020, The Arqma Network
// Copyright (c)2020, Gary Rusher
// Portions of this software are available under BSD-3 license. Please see ORIGINAL-LICENSE for details

// All rights reserved.

// Authors and copyright holders give permission for following:

// 1. Redistribution and use in source and binary forms WITHOUT modification.

// 2. Modification of the source form for your own personal use.

// As long as the following conditions are met:

// 3. You must not distribute modified copies of the work to third parties. This includes
//    posting the work online, or hosting copies of the modified work for download.

// 4. Any derivative version of this work is also covered by this license, including point 8.

// 5. Neither the name of the copyright holders nor the names of the authors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.

// 6. You agree that this licence is governed by and shall be construed in accordance
//    with the laws of England and Wales.

// 7. You agree to submit all disputes arising out of or in connection with this licence
//    to the exclusive jurisdiction of the Courts of England and Wales.

// Authors and copyright holders agree that:

// 8. This licence expires and the work covered by it is released into the
//    public domain on 1st of March 2021

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

let utils = require('./utils.js');
let async = require('async');
let apiInterfaces = require('./apiInterfaces.js')(config.daemon, config.wallet, config.api);
let lastHash;

let POOL_NONCE_SIZE = 16 + 1; // +1 for old XMR/new TRTL bugs
let EXTRA_NONCE_TEMPLATE = "02" + POOL_NONCE_SIZE.toString(16) + "00".repeat(POOL_NONCE_SIZE);
let POOL_NONCE_MM_SIZE = POOL_NONCE_SIZE + utils.cnUtil.get_merged_mining_nonce_size();
let EXTRA_NONCE_NO_CHILD_TEMPLATE = "02" + POOL_NONCE_MM_SIZE.toString(16) + "00".repeat(POOL_NONCE_MM_SIZE);


let logSystem = 'daemon'
let blockData = JSON.stringify({
        id: "0",
        jsonrpc: "2.0",
        method: 'getlastblockheader',
        params: {}
    })

let templateData = JSON.stringify({
        id: "0",
        jsonrpc: "2.0",
        method: 'getblocktemplate',
        params: {reserve_size: config.poolServer.mergedMining ? POOL_NONCE_MM_SIZE : POOL_NONCE_SIZE, wallet_address: config.poolServer.poolAddress}
    })


require('./exceptionWriter.js')(logSystem);


function runInterval(){
    async.waterfall([
	function(callback) {
	  apiInterfaces.jsonHttpRequest(config.daemon.host, config.daemon.port, blockData , function(err, res){
            if(err){
	            log('error', logSystem, '%s error from daemon', [config.coin]);
                setTimeout(runInterval, 3000);
                return;
            }
            if (res && res.result && res.result.status === "OK" && res.result.hasOwnProperty('block_header')){
                let hash = res.result.block_header.hash.toString('hex');
                if (!lastHash || lastHash !== hash) {
		    lastHash = hash
	            log('info', logSystem, '%s found new hash %s', [config.coin, hash]);
                    callback(null, true);
                    return;
                } else if (config.daemon.alwaysPoll || false) {
                    callback(null, true);
                    return;
                }else{
                    callback(true);
                    return;
                }
            } else {
	            log('error', logSystem, 'bad reponse from daemon');
                setTimeout(runInterval, 3000);
                return;
            }
        });
	},
	function(getbc, callback) {
	    apiInterfaces.jsonHttpRequest(config.daemon.host, config.daemon.port, templateData, function(err, res) {
	        if (err) {
		    log('error', logSystem, 'Error polling getblocktemplate %j', [err])
		    callback(null)
		    return
		}
		if (res.error) {
                    log('error', logSystem, 'Error polling getblocktemplate %j', [res.error])
                    callback(null)
                    return
                }
	        process.send({type: 'BlockTemplate', block: res.result})
	        callback(null)
	    })
	}
    ],
    function(error) {
	if (error){}
        setTimeout(function() {
            runInterval()
        }, config.poolServer.blockRefreshInterval)
    })
}

function runZmq() {
    let zmqDaemon = require("./zmqDaemon.js")
    let zmqDirector = zmqDaemon.startZMQ()
    zmqDirector.subscribe(x => {
                        let json = JSON.parse(x.toString()).result
                        process.send({
                            type: 'BlockTemplate',
                            block: json
                        })
                        log('info', logSystem, '%s ZMQ found new blockhashing_blob %s', [config.coin, json.blockhashing_blob]);
                    })
    zmqDaemon.sendMessage('get_block_template', config.poolServer.poolAddress)
}

if (config.zmq.enabled) {
    runZmq()
} else {
    runInterval()
}
