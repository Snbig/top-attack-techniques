<template>
    <div>
        <ul>
            <li v-for="(technique, i) of rankedList?.slice(0, 10)" :key="i" class="list-item"
                :class="{ 'active': activeItemId === i }">
                <div class="flex-1 min-w-0" @click="$emit('setActiveIndex', i)">
                    <span class="rank-num">{{ i + 1 }}.</span>
                    <span class="ml-1 mr-1 highlight">{{ technique.tid }}</span>
                    <span class="technique-name">{{ technique.name }}</span>
                </div>
                <div class="flex items-center gap-2 shrink-0 ml-2" @click.stop>
                    <span class="text-xs whitespace-nowrap">W={{ technique.weight ?? 2 }}</span>
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
                                <span class="text-xs ndi-badge"
                                    :class="ndiClass(technique.weight || 5, technique.detection_level)">
                                    {{ (technique.weight || 5) * technique.detection_level }}/30
                        </span>
                    </template>
                    <span v-else class="text-xs text-gray-400 italic">—</span>
                </div>
                <button v-if="allowDelete" @click="$emit('deleteTechnique', i)" aria-label="delete technique">
                    <i class="pi pi-trash"></i>
                </button>
            </li>
        </ul>
    </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import { type Technique } from "@/data/DataTypes";
export default defineComponent({
    props: {
        rankedList: {
            type: Array<Technique>,
            required: true
        },
        activeItemId: {
            type: Number,
            default: 0,
        },
        allowDelete: Boolean
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
.calculator-list .list-item {
    @apply border-ctid-black border-[1px] -mt-[1px] px-5 py-3 text-lg cursor-pointer flex items-center gap-2 uppercase font-medium;
    font-family: "Fira Sans Extra Condensed", sans-serif;

}

.calculator-list .list-item.active {
    @apply bg-ctid-navy text-white
}

.calculator-list .list-item.active .highlight {
    @apply text-ctid-light-blue
}

.list-item i {
    visibility: hidden;
}

.list-item:hover i {
    visibility: visible;
}

.rank-num {
    @apply mr-1;
}

.technique-name {
    @apply truncate;
}

.d-label {
    @apply flex items-center gap-0.5 text-xs font-normal normal-case cursor-pointer;
}

.d-select {
    @apply border border-gray-400 rounded px-1 py-0.5 text-xs bg-white text-gray-800 cursor-pointer;
    width: 36px;
}

.calculator-list .list-item.active .d-select {
    @apply bg-ctid-navy border-gray-500 text-white;
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

.calculator-list .list-item.active .ndi-low {
    @apply bg-red-800 text-red-100;
}

.calculator-list .list-item.active .ndi-mid {
    @apply bg-yellow-700 text-yellow-100;
}

.calculator-list .list-item.active .ndi-high {
    @apply bg-green-700 text-green-100;
}
</style>