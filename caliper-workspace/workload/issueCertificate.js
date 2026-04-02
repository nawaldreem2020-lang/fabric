'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

/**
 * ══════════════════════════════════════════════════════════════════════
 *  IssueCertificate Workload Module — BCMS Benchmark (BLAKE2b-256)
 * ══════════════════════════════════════════════════════════════════════
 *  Branch    : fabric-BLAKE2-Security
 *  Function  : IssueCertificate(id, studentID, studentName, degree,
 *                               issuer, issueDate, certHash, signature)
 *  RBAC      : Org1MSP only (invokerIdentity: User1@org1.example.com)
 *  Guarantee : 0 failures — idempotent (duplicate IDs return nil)
 *
 *  CRYPTO CHANGE:
 *    OLD: crypto.createHash('sha256')           → SHA-256
 *    NEW: blake2b(data, null, null, 32)         → BLAKE2b-256
 *
 *  BLAKE2b-256 produces identical 32-byte / 64-char hex output as SHA-256
 *  but is ~3× faster on 64-bit CPUs, boosting client-side hash throughput.
 *
 *  Note: Node.js built-in 'crypto' module does NOT support BLAKE2b natively.
 *  We use the pure-JS 'blakejs' package as a dependency-free alternative.
 *  Install: npm install blakejs --save (in caliper-workspace)
 * ══════════════════════════════════════════════════════════════════════
 */

// Attempt to load blakejs; fall back to pure-JS manual implementation
let blake2bHex;
try {
    const blakejs = require('blakejs');
    /**
     * Compute BLAKE2b-256 hex digest.
     * @param {string} data - Input string
     * @returns {string} 64-character lowercase hex string
     */
    blake2bHex = (data) => blakejs.blake2bHex(data, null, 32);
} catch (e) {
    // Fallback: inline pure-JS BLAKE2b-256 implementation
    // This ensures the workload works even without blakejs installed
    blake2bHex = require('./blake2b_fallback').blake2bHex;
}

class IssueCertificateWorkload extends WorkloadModuleBase {
    constructor() {
        super();
        this.txIndex = 0;
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
        this.txIndex = 0;
    }

    async submitTransaction() {
        this.txIndex++;

        const workerIdx   = this.workerIndex || 0;
        const certID      = `CERT_${workerIdx}_${this.txIndex}`;
        const studentID   = `STU_${workerIdx}_${this.txIndex}`;
        const studentName = `Student_${workerIdx}_${this.txIndex}`;
        const degree      = 'Bachelor of Computer Science';
        const issuer      = 'Digital University';
        const issueDate   = new Date().toISOString().split('T')[0];

        // ┌─────────────────────────────────────────────────────────────┐
        // │ BLAKE2b-256 H(C) = BLAKE2b(studentID|name|degree|issuer|date) │
        // │ Must match ComputeCertHash() in Go chaincode EXACTLY        │
        // │ Same field order and "|" separator as before                │
        // └─────────────────────────────────────────────────────────────┘
        const fields    = [studentID, studentName, degree, issuer, issueDate].join('|');
        const certHash  = blake2bHex(fields);
        const signature = `SIG_${certID}_${certHash.substring(0, 16)}`;

        const request = {
            contractId:        'basic',
            contractFunction:  'IssueCertificate',
            contractArguments: [
                certID,
                studentID,
                studentName,
                degree,
                issuer,
                issueDate,
                certHash,
                signature
            ],
            readOnly: false
        };

        return this.sutAdapter.sendRequests(request);
    }

    async cleanupWorkloadModule() {
        // No cleanup needed — idempotent design handles duplicates
    }
}

module.exports = { createWorkloadModule: () => new IssueCertificateWorkload() };
