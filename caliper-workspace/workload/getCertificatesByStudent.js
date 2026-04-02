'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

/**
 * ══════════════════════════════════════════════════════════════════════
 * GetCertificatesByStudent Workload Module — BCMS Benchmark (BLAKE3)
 * ══════════════════════════════════════════════════════════════════════
 * Function  : GetCertificatesByStudent(studentID) → []*Certificate
 * RBAC      : Public read (any org)
 * Guarantee : 0 failures — returns certificates containing BLAKE3 hashes
 * Note      : readOnly:true — utilizes CouchDB rich query performance
 * ══════════════════════════════════════════════════════════════════════
 */
class GetCertificatesByStudentWorkload extends WorkloadModuleBase {
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
        const workerIdx = this.workerIndex || 0;

        // استهداف هوية الطالب التي تم استخدامها في جولة الإصدار (IssueCertificate)
        // ملاحظة: تأكد من أن نمط studentID هنا يطابق النمط في ملف الإرسال تماماً
        const studentID = `STU_${workerIdx}_${this.txIndex}`;

        const request = {
            contractId:        'basic',
            contractFunction:  'GetCertificatesByStudent',
            contractArguments: [studentID],
            readOnly:          true  // استعلام مباشر من الـ Peer لتقليل زمن الاستجابة (Latency)
        };

        return this.sutAdapter.sendRequests(request);
    }

    async cleanupWorkloadModule() {
        // لا يوجد تنظيف مطلوب
    }
}

module.exports = { createWorkloadModule: () => new GetCertificatesByStudentWorkload() };
