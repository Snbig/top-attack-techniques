<template>
    <div id="calculator" class="pb-20">
        <div class="w-5/6 mx-auto pt-20">
            <div class="text-center">
                <h1 class="uppercase font-bold text-5xl">Your Top 10 Techniques</h1>
                <p class="text-sm text-gray-500 mt-1">ATT&CK v{{ calculatorStore.attackVersion }} · {{ rankedList.length }} techniques</p>
            </div>
            <div class="w-full h-auto lg:border-0 border-[1px] border-ctid-black mt-4 mb-6 py-2 lg:py-0">
                <SystemScoreSection />
            </div>
        </div>
        <div class="w-5/6 mx-auto mb-6">
            <div class="bg-ctid-light-gray border border-ctid-black rounded-lg p-4">
                <div class="flex flex-wrap items-center justify-between">
                    <div>
                        <h3 class="font-bold text-lg">Normalized Detection Index (NDI)</h3>
                        <p class="text-sm text-gray-600">
                            Based on <strong>{{ ndiScoredCount }}</strong> of {{ rankedList.length }} techniques with D scores
                        </p>
                    </div>
                    <div class="flex items-center gap-6">
                        <div class="text-center">
                            <div class="text-3xl font-bold" :class="ndiColorClass">{{ overallNDI }}%</div>
                            <div class="text-xs text-gray-500">Overall NDI</div>
                        </div>
                        <div class="text-center">
                            <div class="text-xl font-semibold">{{ ndiNumerator }}/{{ ndiDenominator }}</div>
                            <div class="text-xs text-gray-500 tex2jax_process">\(W \times D\) / \(W \times D_{\max}\)</div>
                        </div>
                        <div class="border-l border-gray-300 pl-4">
                            <div class="flex items-center gap-2 text-xs">
                                <span class="inline-block w-3 h-3 rounded" style="background:#FF0000"></span> 0%
                                <span class="inline-block w-3 h-3 rounded ml-2" style="background:#FFFF00"></span> 50%
                                <span class="inline-block w-3 h-3 rounded ml-2" style="background:#00FF00"></span> 100%
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="bg-gray-100 border border-gray-300 rounded-lg p-3 mt-2 text-xs text-gray-700 leading-relaxed tex2jax_process">
                <span class="font-semibold">NDI Algorithm:</span>
                $$ \text{NDI} = \frac{\sum (W \times D)}{\sum (W \times D_{\max})} \times 100 $$
                <br class="hidden lg:block" />
                <span class="inline lg:ml-4">\(W\) = Weight (1–10) derived from relative rank within your displayed technique set</span>
                <span class="block lg:inline mt-1 lg:mt-0 lg:ml-4">\(D\) = Detection Level (0–3) provided by user after SOC analysis</span>
                <span class="block lg:inline mt-1 lg:mt-0 lg:ml-4">\(D\) &gt; \(0\) required &mdash; unscored TTPs excluded</span>
            </div>
        </div>
        <top-ten-wrapper :ranked-list="rankedList" :allowDelete="true" @delete-technique="(i) => deleteTechnique(i)"
            @update-detection-level="(e) => updateDetectionLevel(e)"
            @import-scores="(e) => importScores(e)" />
    </div>
</template>

<script lang="ts">
import { defineComponent, toRaw } from "vue";
import TopTenWrapper from "../components/TopTenWrapper.vue";
import type { Technique } from "@/data/DataTypes";
import { useCalculatorStore, type CalculatorStore } from "../stores/calculator.store";
import SystemScoreSection from "../components/SystemScoreSection.vue"
export default defineComponent({
    components: { SystemScoreSection, TopTenWrapper },
    data() {
        return {
            calculatorStore: useCalculatorStore(),
            activeItemId: 0,
            rankedList: Array<Technique>
        };
    },
    computed: {
        filters() {
            return this.calculatorStore.activeFilters;
        },
        scores() {
            return this.calculatorStore.systemScoreObj;
        },
        overallNDI(): string {
            const { ndi } = this.computeNDI()
            return ndi.toFixed(1)
        },
        ndiNumerator(): number {
            return this.computeNDI().numerator
        },
        ndiDenominator(): number {
            return this.computeNDI().denominator
        },
        ndiScoredCount(): number {
            let count = 0
            for (const t of (this.rankedList || [])) {
                if (t.detection_level !== null && t.detection_level !== undefined) count++
                if (t.subtechniques) {
                    for (const sub of t.subtechniques) {
                        if (sub.detection_level !== null && sub.detection_level !== undefined) count++
                    }
                }
            }
            return count
        },
        ndiColorClass(): string {
            const ndi = this.computeNDI().ndi
            if (ndi >= 70) return 'text-green-600'
            if (ndi >= 40) return 'text-yellow-500'
            return 'text-red-500'
        },
    },
    methods: {
        computeNDI(): { ndi: number; numerator: number; denominator: number } {
            let numerator = 0
            let denominator = 0
            let scoredCount = 0
            const list = this.rankedList || []
            for (const t of list) {
                // Check main technique D score
                const d = t.detection_level
                if (d !== null && d !== undefined) {
                    const w = t.weight || 2
                    numerator += w * d
                    denominator += w * 3
                    scoredCount++
                }
                // Check subtechnique D scores
                if (t.subtechniques) {
                    for (const sub of t.subtechniques) {
                        const sd = sub.detection_level
                        if (sd !== null && sd !== undefined) {
                            const sw = sub.weight || 2
                            numerator += sw * sd
                            denominator += sw * 3
                            scoredCount++
                        }
                    }
                }
            }
            const ndi = scoredCount > 0 && denominator > 0
                ? parseFloat(((numerator / denominator) * 100).toFixed(2))
                : 0
            return { ndi, numerator, denominator }
        },
        deleteTechnique(index: number) {
            this.rankedList.splice(index, 1)
        },
        updateDetectionLevel(e: { index: number; value: number | null }) {
            if (e.index >= 0 && e.index < this.rankedList.length) {
                this.rankedList[e.index].detection_level = e.value
            }
        },
        importScores(scores: Array<{ tid: string; detection_level: number }>) {
            let matched = 0
            for (const { tid, detection_level } of scores) {
                // Try to match as a top-level technique
                const technique = this.rankedList.find(t => t.tid === tid)
                if (technique) {
                    technique.detection_level = detection_level
                    matched++
                    continue
                }
                // Try to match as a subtechnique
                for (const t of this.rankedList) {
                    const sub = (t.subtechniques || []).find(s => s.tid === tid)
                    if (sub) {
                        sub.detection_level = detection_level
                        matched++
                        break
                    }
                }
            }
            if (matched > 0) {
                // Trigger reactivity by reassigning (for computed properties to recompute)
                this.rankedList = [...this.rankedList]
            }
        },
        setRankedList() {
            let filteredList = structuredClone(toRaw(this.calculatorStore.techniques));
            // Clear any pre-set detection_level — user must provide D scores manually
            for (const t of filteredList) {
                t.detection_level = null
                for (const sub of t.subtechniques) {
                    sub.detection_level = null
                }
            }
            filteredList = this.applyScores(filteredList)
            filteredList = this.applyFilters(filteredList)
            filteredList.sort(
                (a, b) => b.adjusted_score - a.adjusted_score
            );
            // Compute W=1-10 within the displayed top-10 set only
            const topN = Math.min(10, filteredList.length)
            for (let i = 0; i < filteredList.length; i++) {
                const w = i < topN ? 10 - i : 1   // rank 1→10, rank 2→9, ..., rank 10→1, beyond→1
                filteredList[i].weight = w
                for (const sub of (filteredList[i].subtechniques || [])) {
                    sub.weight = w
                }
            }
            this.rankedList = filteredList
        },
        applyFilters(filteredList: Array<Technique>): Array<Technique> {
            const newFilterList = []
            // if there are no filters selected, then return full list of techniques
            if (this.filters.nist.size === 0 && this.filters.cis.size === 0 && this.filters.detection.size === 0 && this.filters.os.size === 0) {
                return filteredList;
            }
            for (const technique of filteredList) {
                if (this.checkForNist(technique) && this.checkForCis(technique) && this.checkForDetection(technique) && this.checkForOs(technique)) {
                    newFilterList.push(technique)
                }
            }
            return newFilterList
        },
        checkForCis(technique: Technique): boolean {
            if (this.filters.cis.size === 0) { return true }
            for (const property of this.filters.cis) {
                if (technique.cis_controls && technique.cis_controls.find(n => n === property)) {
                    return true;
                }
            }
            return false;
        },
        checkForNist(technique: Technique): boolean {
            if (this.filters.nist.size === 0) { return true }
            for (const property of this.filters.nist) {
                if (technique.nist_controls && technique.nist_controls.find(n => n === property)) {
                    return true;
                }
            }
            return false;
        },
        checkForOs(technique: Technique): boolean {
            if (this.filters.os.size === 0) { return true }
            for (const property of this.filters.os) {
                if (technique.platforms && technique.platforms.find(n => n === property)) {
                    return true;
                }
            }
            return false;
        },
        checkForDetection(technique: Technique): boolean {
            if (this.filters.detection.size === 0) { return true }
            for (const filterProp of this.filters.detection) {
                const key = this.calculatorStore.filterProperties.detection.options.find(i => i.name === filterProp)
                if (technique[key.id]) {
                    return true;
                }
            }
            return false;
        },
        applyScores(filteredList: Array<Technique>): Array<Technique> {
            type SystemScoreKeys = (keyof CalculatorStore["systemScoreObj"])[];
            filteredList = filteredList.map((technique) => {
                let score_adjustment = 1
                for (const monitoringType of Object.keys(this.scores) as SystemScoreKeys) {
                    if (technique[`${monitoringType}_coverage`]) {
                        score_adjustment += 1 / 5 * this.scores[monitoringType].value;
                    }
                }
                technique.adjusted_score = technique.cumulative_score * score_adjustment
                return technique;
            })
            return filteredList
        },

    },
    beforeMount() {
        this.setRankedList();
    },
});
</script>

<style scoped></style>
