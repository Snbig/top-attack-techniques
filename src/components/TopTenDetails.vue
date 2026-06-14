<template>
    <div class="container-body">
        <h3>Description</h3>
        <div class="description" v-html="getMarkdown(technique.description)"></div>
        <div v-if="technique.subtechniques.length > 0" class="subtechniques">
            <h3 class="mt-4">Subtechniques</h3>
            <Accordion class="mt-2">
                <AccordionTab v-for="(subtechnique, j) in technique.subtechniques" :key="subtechnique.tid">
                    <template #header>
                        <div class="flex items-center justify-between w-full pr-2">
                            <h4 class="truncate">
                                <span class="highlight">
                                    {{ subtechnique.tid }}
                                </span>
                                {{ subtechnique.name }}
                            </h4>
                            <div class="flex items-center gap-2 shrink-0 ml-2" @click.stop>
                                <span class="text-xs">W={{ subtechnique.weight ?? 5 }}</span>
                                <label class="d-label">
                                    D
                                    <select class="d-select" :value="subtechnique.detection_level ?? ''"
                                        @change="onSubDChange(j, ($event.target as HTMLSelectElement).value)">
                                        <option value="">—</option>
                                        <option :value="0">0</option>
                                        <option :value="1">1</option>
                                        <option :value="2">2</option>
                                        <option :value="3">3</option>
                                    </select>
                                </label>
                                <template v-if="subtechnique.detection_level !== null && subtechnique.detection_level !== undefined">
                                    <span class="ndi-badge"
                                        :class="ndiClass(subtechnique.weight ?? 5, subtechnique.detection_level)">
                                        {{ (subtechnique.weight ?? 5) * subtechnique.detection_level }}/30
                                    </span>
                                </template>
                                <span v-else class="text-xs text-gray-400 italic">—</span>
                            </div>
                        </div>
                    </template>
                    <h4>Subtechnique Description</h4>
                    <div class="description" v-html="getMarkdown(subtechnique.description)"></div>
                    <div v-if="subtechnique.mitigations.length > 0">
                        <h4 class="mt-4">Mitigations</h4>
                        <ul class="mitigations">
                            <li v-for="mitigation of subtechnique.mitigations" :key="mitigation.mid">
                                <h5>{{ mitigation.mid }} - {{ mitigation.name }}</h5>
                                <div class="description" v-html="getMarkdown(mitigation.description)"></div>
                            </li>
                        </ul>
                    </div>
                    <div v-if="subtechnique.detection">
                        <h4 class="mt-4">Detections</h4>
                        <div class="description" v-html="getMarkdown(subtechnique.detection)"></div>
                    </div>
                </AccordionTab>
            </Accordion>
        </div>
        <div v-if="technique.mitigations.length > 0">
            <h3 class="mt-4">Mitigations</h3>
            <ul class="mitigations">
                <li v-for="mitigation of technique.mitigations" :key="mitigation.mid">
                    <h4>
                        {{ mitigation.mid }} - {{ mitigation.name }}
                    </h4>
                    <div class="description" v-html="getMarkdown(mitigation.description)"></div>
                </li>
            </ul>
        </div>
        <div v-if="technique.detection">
            <h3 class="mt-4">Detections</h3>
            <div class="description" v-html="getMarkdown(technique.detection)"></div>
        </div>
        <div v-if="technique.url">
            <h3 class="mt-4">References</h3>
            <ul>
                <li>
                    <a class=" text-ctid-blue hover:underline" target="_blank" :href="technique.url">
                        {{ technique.url }}
                    </a>
                </li>
            </ul>
        </div>
    </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import Accordion from "primevue/accordion";
import AccordionTab from "primevue/accordiontab";
import { marked } from 'marked';

export default defineComponent({
    components: { Accordion, AccordionTab },
    props: {
        technique: {}
    },
    methods: {
        getMarkdown(text: string) {
            if (!text) {
                return ""
            }
            const t = marked(text)
            return t.replaceAll("<a ", '<a target="_blank" ')
        },
        onSubDChange(subIndex: number, value: string) {
            const d = value === "" ? null : parseInt(value, 10)
            if (this.technique && this.technique.subtechniques && this.technique.subtechniques[subIndex]) {
                this.technique.subtechniques[subIndex].detection_level = d
            }
        },
        ndiClass(w: number, d: number): string {
            const ndi = w * d
            if (ndi >= 6) return 'ndi-high'
            if (ndi >= 3) return 'ndi-mid'
            return 'ndi-low'
        }
    }
});
</script>

<style scoped>
.container-body {
    @apply py-4 px-6
}

.container-body h3 {
    @apply uppercase font-bold text-lg
}

.container-body h4 {
    @apply uppercase font-bold
}

ul {
    @apply list-disc ml-6
}

ul p {
    @apply pl-4
}

.mitigations h4, .mitigations h5 {
    @apply uppercase font-bold
}

.d-label {
    @apply flex items-center gap-0.5 text-xs font-normal normal-case cursor-pointer;
}

.d-select {
    @apply border border-gray-400 rounded px-1 py-0.5 text-xs bg-white text-gray-800 cursor-pointer;
    width: 36px;
}

.ndi-badge {
    @apply text-xs font-bold px-1.5 py-0.5 rounded;
}

.ndi-low {
    @apply bg-red-100 text-red-700;
}

.ndi-mid {
    @apply bg-yellow-100 text-yellow-700;
}

.ndi-high {
    @apply bg-green-100 text-green-700;
}
</style>