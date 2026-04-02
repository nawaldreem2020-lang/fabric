'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

/**
 * ══════════════════════════════════════════════════════════════════════
 * RevokeCertificate Workload Module — BCMS Benchmark (BLAKE3 Edition)
 * ══════════════════════════════════════════════════════════════════════
 * Function  : RevokeCertificate(id) → error
 * RBAC      : Org2MSP authorized (Org1 or Org2)
 * Guarantee : 0 failures — idempotent
 * Note      : Targets certificates issued with BLAKE3 IDs
 * ══════════════════════════════════════════════════════════════════════
 */
class RevokeCertificateWorkload extends WorkloadModuleBase {
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

        // يجب أن يطابق نمط الـ ID تماماً ما تم استخدامه في IssueCertificate (BLAKE3)
        // أضفنا _B3_ لضمان استهداف الشهادات الصحيحة في قاعدة البيانات
        const certID = `CERT_B3_${workerIdx}_${this.txIndex}`;

        const request = {
            contractId:        'basic',
            contractFunction:  'RevokeCertificate',
            contractArguments: [certID],
            readOnly:          false    // عملية كتابة — تمر عبر الـ Orderer والـ Endorsement
        };

        return this.sutAdapter.sendRequests(request);
    }

    async cleanupWorkloadModule() {
        // لا يوجد تنظيف مطلوب — التصميم يدعم التكرار (Idempotent)
    }
}

module.exports = { createWorkloadModule: () => new RevokeCertificateWorkload() };
