'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

/**
 * ══════════════════════════════════════════════════════════════════════
 * QueryAllCertificates Workload Module — BCMS Benchmark (BLAKE3 Edition)
 * ══════════════════════════════════════════════════════════════════════
 * Function  : QueryAllCertificates() → []*Certificate
 * RBAC      : Public read (any org)
 * Guarantee : 0 failures — returns certificates with BLAKE3 hash tags
 * Note      : readOnly:true — direct peer query (CouchDB performance)
 * ══════════════════════════════════════════════════════════════════════
 */
class QueryAllCertificatesWorkload extends WorkloadModuleBase {
    constructor() {
        super();
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
    }

    async submitTransaction() {
        const request = {
            contractId:        'basic',
            contractFunction:  'QueryAllCertificates',
            contractArguments: [],      // لا توجد وسائط — العقد الذكي يقرأ الحالة الحالية فقط
            readOnly:          true     // أساسي: تجاوز Orderer لزيادة سرعة استرجاع البيانات
        };

        return this.sutAdapter.sendRequests(request);
    }

    async cleanupWorkloadModule() {
        // لا يوجد تنظيف مطلوب
    }
}

module.exports = { createWorkloadModule: () => new QueryAllCertificatesWorkload() };
