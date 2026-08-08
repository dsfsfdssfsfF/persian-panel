'use strict';

const grpc       = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const path       = require('path');
const fs         = require('fs');

const XRAY_API_ADDR = '127.0.0.1:10085';

// ══════════════════════════════════
// Proto definitions (inline)
// ══════════════════════════════════
const HANDLER_PROTO = `
syntax = "proto3";
package xray.app.proxyman.command;

service HandlerService {
  rpc AddInbound(AddInboundRequest) returns (AddInboundResponse) {}
  rpc RemoveInbound(RemoveInboundRequest) returns (RemoveInboundResponse) {}
  rpc AlterInbound(AlterInboundRequest) returns (AlterInboundResponse) {}
}

message AddInboundRequest { bytes inbound = 1; }
message AddInboundResponse {}
message RemoveInboundRequest { string tag = 1; }
message RemoveInboundResponse {}
message AlterInboundRequest {
  string tag = 1;
  bytes operation = 2;
}
message AlterInboundResponse {}
`;

const STATS_PROTO = `
syntax = "proto3";
package xray.app.stats.command;

service StatsService {
  rpc GetStats(GetStatsRequest) returns (GetStatsResponse) {}
  rpc QueryStats(QueryStatsRequest) returns (QueryStatsResponse) {}
}

message GetStatsRequest {
  string name = 1;
  bool reset = 2;
}
message GetStatsResponse { Stat stat = 1; }
message Stat {
  string name = 1;
  int64 value = 2;
}
message QueryStatsRequest {
  string pattern = 1;
  bool reset = 2;
}
message QueryStatsResponse { repeated Stat stat = 1; }
`;

// ══════════════════════════════════
// gRPC Clients
// ══════════════════════════════════
let handlerClient = null;
let statsClient   = null;

function getHandlerClient() {
  if (!handlerClient) {
    try {
      const tmpFile = '/tmp/handler.proto';
      fs.writeFileSync(tmpFile, HANDLER_PROTO);
      const def = protoLoader.loadSync(tmpFile, {
        keepCase: true, longs: String, enums: String, defaults: true, oneofs: true
      });
      const proto = grpc.loadPackageDefinition(def);
      handlerClient = new proto.xray.app.proxyman.command.HandlerService(
        XRAY_API_ADDR,
        grpc.credentials.createInsecure()
      );
    } catch (e) {
      console.error('[xray-api] handler client error:', e.message);
    }
  }
  return handlerClient;
}

function getStatsClient() {
  if (!statsClient) {
    try {
      const tmpFile = '/tmp/stats.proto';
      fs.writeFileSync(tmpFile, STATS_PROTO);
      const def = protoLoader.loadSync(tmpFile, {
        keepCase: true, longs: String, enums: String, defaults: true, oneofs: true
      });
      const proto = grpc.loadPackageDefinition(def);
      statsClient = new proto.xray.app.stats.command.StatsService(
        XRAY_API_ADDR,
        grpc.credentials.createInsecure()
      );
    } catch (e) {
      console.error('[xray-api] stats client error:', e.message);
    }
  }
  return statsClient;
}

// ══════════════════════════════════
// Query Traffic Stats
// ══════════════════════════════════
function queryStats(pattern = '', reset = false) {
  return new Promise((resolve) => {
    const client = getStatsClient();
    if (!client) return resolve([]);
    client.QueryStats({ pattern, reset }, (err, res) => {
      if (err) { console.error('[xray-api] queryStats:', err.message); return resolve([]); }
      resolve(res?.stat || []);
    });
  });
}

function getUserTraffic(email, reset = false) {
  return new Promise(async (resolve) => {
    try {
      const stats = await queryStats(`user>>>`, reset);
      let up = 0, down = 0;
      stats.forEach(s => {
        if (s.name.includes(`>>>${email}>>>`)) {
          if (s.name.includes('uplink'))   up   += parseInt(s.value) || 0;
          if (s.name.includes('downlink')) down += parseInt(s.value) || 0;
        }
      });
      resolve({ up, down, total: up + down });
    } catch (e) {
      resolve({ up: 0, down: 0, total: 0 });
    }
  });
}

async function getAllUsersTraffic(reset = false) {
  const stats = await queryStats('user>>>', reset);
  const result = {};
  stats.forEach(s => {
    const parts = s.name.split('>>>');
    if (parts.length >= 4) {
      const email = parts[1];
      const type  = parts[3];
      if (!result[email]) result[email] = { up: 0, down: 0, total: 0 };
      const val = parseInt(s.value) || 0;
      if (type === 'uplink')   result[email].up   += val;
      if (type === 'downlink') result[email].down += val;
      result[email].total = result[email].up + result[email].down;
    }
  });
  return result;
}

module.exports = {
  queryStats,
  getUserTraffic,
  getAllUsersTraffic,
  getHandlerClient,
  getStatsClient
};
