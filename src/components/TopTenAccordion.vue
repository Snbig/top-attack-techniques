<template>
    <div>
        <Accordion :active-index="activeItemId">
            <AccordionTab v-for="(technique, i) of rankedList?.slice(0, results)" :key="i">
                <template #header>
                    <div class="flex items-center justify-between w-full pr-2">
                        <h2 class="truncate">
                            {{ i + 1 }}.
                            <span class="highlight">
                                {{ technique.tid }}
                            </span>
                            {{ technique.name }}
                        </h2>
                        <div class="flex items-center gap-2 shrink-0 ml-2" @click.stop>
                            <label class="d-label">
                                D
                                <select class="d-select" :value="technique.detection_level ?? ''"
                                    @change="onDChange(i, ($event.target as HTMLSelectElement).value)">
                                    <option value="">—</option>
                                    <option :value="0">0</option>
                                    <option :value="1">1</option>
                                    <option :value="2">2</option>
                                    <option :value="3">3</option>
                                </select>
                            </label>
                            <template v-if="technique.detection_level !== null && technique.detection_level !== undefined">
                                <span class="ndi-badge" :class="ndiClass(technique.weight || 5, technique.detection_level)">
                                    W={{ technique.weight ?? 5 }} NDI={{ (technique.weight || 5) * technique.detection_level }}/30
                                </span>
                            </template>
                            <span v-else class="text-xs text-gray-400 italic">—</span>
                        </div>
                    </div>
                </template>
                <TopTenDetails :technique="technique" />
            </AccordionTab>
        </Accordion>
    </div>
</template>

<script lang="ts">
import { defineComponent, type PropType } from "vue";
import Accordion from "primevue/accordion";
import AccordionTab from "primevue/accordiontab";
import TopTenDetails from "./TopTenDetails.vue";
import { type Technique } from "@/data/DataTypes";

export default defineComponent({
    components: { Accordion, AccordionTab, TopTenDetails },
    props: {
        rankedList: {
            type: Array as PropType<Technique[]>,
            required: true
        },
        activeItemId: Number,
        results: {
            type: Number,
            default: 10
        }
    },
    emits: ["updateDetectionLevel"],
    methods: {
        onDChange(index: number, value: string) {
            const d = value === "" ? null : parseInt(value, 10)
            this.$emit("updateDetectionLevel", { index, value: d })
        },
        ndiClass(w: number, d: number): string {
            const ndi = w * d
            if (ndi >= 6) return 'ndi-high'
            if (ndi >= 3) return 'ndi-mid'
            return 'ndi-low'
        }
    },
});
</script>

<style scoped>
.d-label {
    @apply flex items-center gap-0.5 text-xs font-normal cursor-pointer;
}

.d-select {
    @apply border border-gray-400 rounded px-1 py-0.5 text-xs bg-white text-gray-800 cursor-pointer;
    width: 36px;
}

.ndi-badge {
    @apply text-xs font-bold px-1.5 py-0.5 rounded whitespace-nowrap;
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

<style scoped></style>