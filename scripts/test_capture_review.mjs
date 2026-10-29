import assert from 'node:assert/strict';
import { reviewHttpExchange } from '../source/capture_review.js';
const result = reviewHttpExchange({ id: 'fixture', url: 'https://example.invalid/', response: { headers: { 'Content-Type': 'text/html', 'Set-Cookie': ['token=secret; Path=/', 'id=hidden; Secure; HttpOnly; SameSite=Strict'] } } });
assert.equal(result.networkRequests, 0);
assert.equal(result.observations.filter(item => item.code === 'COOKIE_ATTRIBUTE_NOT_OBSERVED').length, 3);
assert(result.observations.every(item => item.verifiedVulnerability === false));
assert(!JSON.stringify(result).includes('secret'));
assert.equal(reviewHttpExchange({url:'https://example.invalid/',response:{headers:{'content-type':'application/json','strict-transport-security':'max-age=100'}}}).observations.length,0);
console.log('PASS passive HTTP observations, secret-free evidence and no vulnerability claims');
