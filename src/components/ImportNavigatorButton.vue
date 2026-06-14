<template>
    <Button label="Import Navigator Layer" icon="pi pi-upload" class="p-button-outlined p-button-sm w-full mt-2"
        @click="openFilePicker" />
    <input ref="fileInput" type="file" accept=".json,application/json" class="hidden" @change="onFileSelected" />
</template>

<script lang="ts">
import { defineComponent } from "vue";
import Button from "primevue/button";

interface NavigatorTechnique {
    techniqueID: string;
    score?: number;
    comment?: string;
    metadata?: Record<string, unknown>[];
    children?: NavigatorTechnique[];
}

interface NavigatorLayer {
    name?: string;
    versions?: Record<string, string>;
    description?: string;
    domain?: string;
    techniques?: NavigatorTechnique[];
    gradient?: Record<string, unknown>;
}

export default defineComponent({
    components: { Button },
    emits: ["importScores"],
    methods: {
        openFilePicker() {
            const input = this.$refs.fileInput as HTMLInputElement
            if (input) {
                input.value = ""
                input.click()
            }
        },
        onFileSelected(event: Event) {
            const input = event.target as HTMLInputElement
            if (!input.files || input.files.length === 0) return

            const file = input.files[0]
            const reader = new FileReader()
            reader.onload = (e) => {
                try {
                    const result = this.parseLayer(e.target?.result as string)
                    if (result.length > 0) {
                        this.$emit("importScores", result)
                        window.alert(`Imported D scores for ${result.length} technique(s) from "${file.name}"`)
                    } else {
                        window.alert("No D scores found in the selected file.")
                    }
                } catch (err) {
                    window.alert("Failed to parse Navigator layer file. Please select a valid JSON file.")
                }
            }
            reader.readAsText(file)
        },
        parseLayer(content: string): Array<{ tid: string; detection_level: number }> {
            const layer: NavigatorLayer = JSON.parse(content)
            const techniques = layer.techniques || []
            const results: Array<{ tid: string; detection_level: number }> = []

            const extractTechnique = (t: NavigatorTechnique) => {
                const tid = t.techniqueID
                if (!tid) return

                // Try to extract D score from the NDI comment
                let d = this.extractDFromComment(t.comment)

                // Fallback: try to infer from score if no comment found
                if (d === null && t.score !== undefined && t.score !== null) {
                    d = this.invertDFromScore(t.score)
                }

                if (d !== null && d >= 0 && d <= 3) {
                    results.push({ tid, detection_level: d })
                }

                // Recursively parse children (subtechniques)
                if (t.children && t.children.length > 0) {
                    for (const child of t.children) {
                        extractTechnique(child)
                    }
                }
            }

            for (const t of techniques) {
                extractTechnique(t)
            }

            return results
        },
        extractDFromComment(comment?: string): number | null {
            if (!comment) return null
            // Match: NDI Detection Level (D): 3
            const match = comment.match(/NDI Detection Level \(D\):\s*(\d)/)
            if (match) {
                return parseInt(match[1], 10)
            }
            return null
        },
        invertDFromScore(score: number): number | null {
            // If score is 0-9 and we don't have weight info, we can't reliably invert.
            // Only handle the common weights (2 is default):
            // score = W * D, so D = score / W
            // Since we don't know W, only handle obvious cases
            if (score === 0) return 0
            if (score === 1) return 1  // W=1, D=1
            if (score === 2) return 1  // W=2, D=1 or W=1, D=2
            if (score === 3) return 1  // W=3, D=1
            if (score === 4) return 2  // W=2, D=2
            if (score === 6) return 2  // W=3, D=2 or W=2, D=3
            if (score === 9) return 3  // W=3, D=3
            return null
        }
    },
});
</script>

<style scoped>
.hidden {
    display: none;
}
</style>
