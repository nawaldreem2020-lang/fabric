'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
// استيراد مكتبة blake3 بدلاً من crypto
const blake3 = require('blake3');

/**
 * ══════════════════════════════════════════════════════════════════════
 * VerifyCertificate Workload Module — BCMS Benchmark (BLAKE3 Edition)
 * ══════════════════════════════════════════════════════════════════════
 * Function  : VerifyCertificate(id, certHash) → VerificationResult
 * RBAC      : Public (any org — readOnly query)
 * Crypto    : BLAKE3 hash computed client-side matching chaincode
 * Note      : readOnly:true — maximum TPS by bypassing the orderer
 * ══════════════════════════════════════════════════════════════════════
 */
class VerifyCertificateWorkload extends WorkloadModuleBase {
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
        // تحديث النمط ليتطابق مع CERT_B3_ المستخدم في عملية الإصدار
        const certID      = `CERT_B3_${workerIdx}_${this.txIndex}`;
        const studentID   = `STU_${workerIdx}_${this.txIndex}`;
        const studentName = `Student_${workerIdx}_${this.txIndex}`;
        const degree      = 'Bachelor of Computer Science';
        const issuer      = 'Digital University';
        const issueDate   = new Date().toISOString().split('T')[0];

        // منطق حساب الهاش يجب أن يطابق دالة ComputeCertHash في العقد الذكي تماماً
        const fields   = [studentID, studentName, degree, issuer, issueDate].join('|');
        
        // حساب الهاش باستخدام BLAKE3 وتحويله إلى hex
        const certHash = blake3.hash(fields).toString('hex');

        const request = {
            contractId:        'basic',
            contractFunction:  'VerifyCertificate',
            // الوسائط المطلوبة للدالة في Go هي (id, certHash)
            contractArguments: [certID, certHash],
            readOnly:          true    // استعلام مباشر من الـ Peer لتحقيق أقصى عدد معاملات (TPS)
        };

        return this.sutAdapter.sendRequests(request);
    }

    async cleanupWorkloadModule() {
        // لا يوجد تنظيف مطلوب
    }
}

module.exports = { createWorkloadModule: () => new VerifyCertificateWorkload() };
