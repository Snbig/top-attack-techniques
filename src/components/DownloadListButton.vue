<template>
    <SplitButton label="Download" @click="downloadAsJson" :model="items" />
</template>

<script lang="ts">
import { defineComponent } from "vue";
import { type Technique, type ExportedTechnique } from "@/data/DataTypes";
import SplitButton from "primevue/splitbutton";
import downloadjs from "downloadjs";
import { useCalculatorStore, type CalculatorStore } from "@/stores/calculator.store";

export default defineComponent({
    components: {
        SplitButton
    },
    props: {
        rankedList: {
            type: Array<Technique>,
            required: true
        },
    },
    data() {
        return {
            calculatorStore: useCalculatorStore(),
            items: [
                {
                    label: 'Download as JSON',
                    command: () => {
                        this.downloadAsJson()
                    }
                },
                {
                    label: 'Download as Navigator Layer',
                    command: () => {
                        this.downloadAsNavigatorLayer()
                    }
                }
            ]
        };
    },
    methods: {
        /** Sanitize control characters from strings to prevent JSON parsing issues. */
        sanitizeText(s: string): string {
            return s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').trim()
        },
        computeOverallNDI(): { ndi: number; numerator: number; denominator: number } {
            let numerator = 0
            let denominator = 0
            let scoredCount = 0
            for (const t of this.rankedList) {
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
        downloadAsJson() {
            const parsedList = [] as Array<ExportedTechnique>;

            this.rankedList.forEach((technique, i) => {
                const t = {
                    rank: i + 1,
                    tid: technique.tid,
                    name: technique.name,
                    description: technique.description,
                    url: technique.url,
                    detection_level: technique.detection_level,
                    score: technique.adjusted_score,
                    network_score: technique.network_score,
                    process_score: technique.process_score,
                    file_score: technique.file_score,
                    cloud_score: technique.cloud_score,
                    hardware_score: technique.hardware_score,
                    mitigations: technique.mitigations,
                    subtechniques: technique.subtechniques,
                    actionability_score: technique.actionability_score,
                    choke_point_score: technique.choke_point_score,
                    prevalence_score: technique.prevalence_score,
                }
                parsedList.push(t);
            })
            downloadjs(JSON.stringify(parsedList, null, 4), "TopTenTechniques.json", "application/json")
        },
        downloadAsNavigatorLayer() {
            const gradient = ["#FF0000", "#FFFF00", "#00FF00"]
            const overallNDI = this.computeOverallNDI()
            let scoredCount = 0
            for (const t of this.rankedList) {
                if (t.detection_level !== null && t.detection_level !== undefined) scoredCount++
                if (t.subtechniques) {
                    for (const sub of t.subtechniques) {
                        if (sub.detection_level !== null && sub.detection_level !== undefined) scoredCount++
                    }
                }
            }
            const ndiDesc = scoredCount > 0
                ? `NDI: ${overallNDI.ndi}% | ${overallNDI.numerator}/${overallNDI.denominator} | Weighted detection coverage across ${scoredCount} scored techniques`
                : `NDI: No techniques scored yet - provide D scores for NDI calculation`
            const layer = {
                "name": "Top 10 ATT&CK Techniques",
                "versions": {
                    "navigator": "4.8.0",
                    "layer": "4.5",
                    "attack": this.calculatorStore.attackVersion,
                },
                "sorting": 3,
                "description": this.sanitizeText(`Top ATT&CK Techniques - ${ndiDesc}`),
                "domain": "enterprise-attack",
                "hideDisabled": true,
                "techniques": [] as Array<Record<string, unknown>>,
                "gradient": {
                    "colors": gradient,
                    "minValue": 0,
                    "maxValue": 9
                },
            }

            // Build lookup: tid -> ranked technique/subtechnique (has D scores from user)
            const rankedMap = new Map<string, Technique>()
            for (const t of this.rankedList) {
                rankedMap.set(t.tid, t)
                for (const sub of (t.subtechniques || [])) {
                    rankedMap.set(sub.tid, sub)
                }
            }

            type SystemScoreKeys = (keyof CalculatorStore["systemScoreObj"])[];
            const allTechniques: Technique[] = (this.calculatorStore.techniques || [])
            for (const technique of allTechniques) {
                // Skip subtechniques — they are already included as children of their parent technique
                if (technique.is_subtechnique) continue;
                const rankedT = rankedMap.get(technique.tid)
                const d = rankedT?.detection_level ?? null
                const isScored = d !== null && d !== undefined
                const subs = technique.subtechniques || []

                // Build children array with ALL subtechniques so Navigator
                // doesn't inherit parent's color to them
                const children: Array<Record<string, unknown>> = []
                for (const sub of subs) {
                    const rankedSub = rankedMap.get(sub.tid)
                    const sd = rankedSub?.detection_level ?? null
                    const subScored = sd !== null && sd !== undefined

                    if (subScored) {
                        const sw = rankedSub?.weight ?? sub.weight ?? 5
                        const sndi = sw * sd
                        const subComment =
                            `NDI Weight (W): ${sw}\nNDI Detection Level (D): ${sd}\nNDI Score (WxD): ${sndi}/30`
                        children.push({
                            "techniqueID": sub.tid,
                            "enabled": true,
                            "score": sndi,
                            "comment": this.sanitizeText(subComment),
                            "metadata": [],
                        })
                    } else {
                        children.push({
                            "techniqueID": sub.tid,
                            "enabled": false,
                            "metadata": [],
                        })
                    }
                }

                const hasSubs = subs.length > 0
                const hasScoredChildren = children.some(c => c.enabled === true)

                if (!isScored && !hasScoredChildren) {
                    // Fully disabled — hidden when hideDisabled is active in Navigator
                    layer.techniques.push({
                        "techniqueID": technique.tid,
                        "enabled": false,
                        "showSubtechniques": false,
                        "metadata": [],
                    })
                    continue
                }

                const entry: Record<string, unknown> = {
                    "techniqueID": technique.tid,
                }

                // Build parent technique entry
                if (isScored) {
                    const rankIndex = this.rankedList.indexOf(rankedT!)
                    const rank = rankIndex >= 0 ? rankIndex + 1 : 0
                    let description = ` Rank: ${rank}`;
                    for (const monitoringType of Object.keys(this.calculatorStore.systemScore) as SystemScoreKeys) {
                        if (technique[`${monitoringType}_score`]) {
                            const monitorType = monitoringType.charAt(0).toUpperCase() + monitoringType.slice(1);
                            const monitorTypeScore = technique[`${monitoringType}_score`].toFixed(2);
                            description += `\n${monitorType} Score: ${monitorTypeScore}`;
                        }
                    }
                    const actionability = `Actionability Score: ${technique.actionability_score?.combined_score?.toFixed(2)}`
                    const chokePoint = `Choke Point Score: ${technique.choke_point_score?.toFixed(2)}`
                    const prevalence = `Prevalence Score: ${technique.prevalence_score?.toFixed(2)}`
                    description += `\n ${actionability}\n ${chokePoint}\n ${prevalence}`

                    const w = rankedT?.weight ?? technique.weight ?? 5
                    const ndi = w * d
                    description += `\n NDI Weight (W): ${w}\n NDI Detection Level (D): ${d}\n NDI Score (WxD): ${ndi}/30`

                    entry["enabled"] = true
                    entry["score"] = ndi
                    entry["comment"] = this.sanitizeText(description)
                    entry["metadata"] = []
                } else {
                    // Parent unscored but has scored children
                    entry["enabled"] = false
                    entry["metadata"] = []
                }

                // Always include children array when technique has subtechniques
                if (hasSubs) {
                    entry["children"] = children
                }

                layer.techniques.push(entry)
            }

            const jsonStr = JSON.stringify(layer, null, 4)
            downloadjs(jsonStr, "TopTechniquesNavigatorLayer.json", "application/json")
        }
    },
});
</script>

<style scoped></style>