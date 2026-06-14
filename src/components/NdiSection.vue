<template>

    <h3>Why NDI Matters</h3>
    <p>The Normalized Detection Index (NDI) is a metric that measures how well your organization can detect
        and respond to the techniques in your Top ATT&CK list. While the scoring methodology
        (Actionability, Choke Point, Prevalence) tells you which techniques are most critical based on threat
        intelligence, NDI tells you how prepared you are to actually handle them.</p>
    <p>By scoring each technique on your detection capability, NDI surfaces blind spots &mdash; techniques
        where your monitoring is weakest relative to their risk. This allows you to prioritize detection
        engineering efforts where they matter most.</p>

    <h3>Framing the Analysis</h3>
    <p>NDI combines two factors for each technique: a <strong>weight (W)</strong> that reflects how critical
        the technique is based on actionability, choke point, prevalence, and your monitoring environment;
        and a <strong>detection level (D)</strong> that reflects your organization's ability to detect it.</p>
    <p>The overall NDI is then computed as a weighted average across all scored TTPs:</p>
    <div class="my-4">$$ \text{NDI} = \frac{\sum (W \times D)}{\sum (W \times D_{\max})} \times 100 $$</div>
    <p>Where \(D_{\max} = 3\) is the maximum possible detection level. The result is a percentage from 0&ndash;100:
        higher values indicate better overall detection coverage for your highest-priority techniques.</p>

    <h3>NDI Weight (W)</h3>
    <p>Every technique is first scored by combining its actionability score, choke point score, and prevalence
        score, all adjusted for your organization's monitoring levels (Network, Process, File, Cloud, Hardware).
        These scores determine the ranked order of your technique list.</p>
    <p>Weight is then assigned <strong>within the displayed top-10 set</strong> based purely on rank.
        The highest-ranked technique receives W=10, the second receives W=9, and so on down to W=1 for the
        tenth-ranked technique. Techniques outside the top 10 all receive W=1. This ensures your top 10 always
        show meaningful weight differentiation:</p>
    <div class="my-4">
        <table class="weight-table">
            <thead>
                <tr>
                    <th>W</th>
                    <th>Applied To</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                <tr><td class="text-center font-bold">10</td><td>Rank #1</td><td>Highest-priority technique in your list</td></tr>
                <tr><td class="text-center font-bold">9</td><td>Rank #2</td><td>Second-highest priority</td></tr>
                <tr><td class="text-center font-bold">8</td><td>Rank #3</td><td>Third-highest priority</td></tr>
                <tr><td class="text-center font-bold">7</td><td>Rank #4</td><td>High priority</td></tr>
                <tr><td class="text-center font-bold">6</td><td>Rank #5</td><td>Above-average priority</td></tr>
                <tr><td class="text-center font-bold">5</td><td>Rank #6</td><td>Moderate priority</td></tr>
                <tr><td class="text-center font-bold">4</td><td>Rank #7</td><td>Slightly below-average priority</td></tr>
                <tr><td class="text-center font-bold">3</td><td>Rank #8</td><td>Lower priority</td></tr>
                <tr><td class="text-center font-bold">2</td><td>Rank #9</td><td>Near-bottom of your top 10</td></tr>
                <tr><td class="text-center font-bold">1</td><td>Rank #10 or beyond</td><td>Lowest priority in your set</td></tr>
            </tbody>
        </table>
    </div>
    <p>Subtechniques inherit the weight of their parent technique. This ensures that the NDI accurately
        reflects the overall importance of a technique family rather than treating subtechniques as
        independent items.</p>

    <h3>Detection Level (D)</h3>
    <p>After your ranked list is generated, you assign a detection level to each technique and subtechnique
        based on your organization's current detection capabilities. This is the human-driven component of
        NDI &mdash; your security analysts evaluate what coverage actually exists for each technique.</p>
    <p>The detection level uses a four-point scale:</p>
    <div class="my-4">
        <table class="detection-table">
            <thead>
                <tr>
                    <th>D Value</th>
                    <th>Label</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td class="text-center font-bold">0</td>
                    <td>No Logs</td>
                    <td>No telemetry source captures activity related to this technique</td>
                </tr>
                <tr>
                    <td class="text-center font-bold">1</td>
                    <td>Raw Logs</td>
                    <td>Telemetry is collected but requires manual review &mdash; no automated alerting</td>
                </tr>
                <tr>
                    <td class="text-center font-bold">2</td>
                    <td>SIEM Alert</td>
                    <td>Correlated alert exists in SIEM or detection platform, but may require analyst
                        triage</td>
                </tr>
                <tr>
                    <td class="text-center font-bold">3</td>
                    <td>Prevention</td>
                    <td>Automated prevention or blocking capability is in place (e.g. EDR block, WAF rule,
                        GPO)</td>
                </tr>
            </tbody>
        </table>
    </div>
    <p>Only techniques with \(D &gt; 0\) contribute to the NDI calculation. Unscored TTPs (\(D = \text{null}\))
        are excluded from both the numerator and denominator, ensuring they don't penalize your overall score.
        This design encourages scoring all relevant techniques without artificially deflating the result.</p>

    <h3>Interpreting NDI</h3>
    <p>The overall NDI percentage gives you a high-level view of your detection posture:</p>
    <ul>
        <li><strong>NDI &ge; 70%</strong> &mdash; Strong detection coverage for your highest-risk techniques.
            Prioritize maintaining coverage as new techniques emerge.</li>
        <li><strong>NDI 40&ndash;69%</strong> &mdash; Moderate coverage. Focus on closing gaps for
            high-weight (W=7+) techniques first, as they have the greatest impact on the overall score.
        </li>
        <li><strong>NDI &lt; 40%</strong> &mdash; Significant gaps. Use the per-technique breakdown
            to identify which critical techniques lack detection coverage and build a remediation plan.
        </li>
    </ul>
    <p>Because NDI weights techniques by their importance, improving detection for a single W=10 technique
        has ten times the impact of improving a W=1 technique. This makes NDI an effective tool for
        prioritizing detection engineering investments.</p>

    <h3>Limitations</h3>
    <p>NDI is a self-assessment tool and its accuracy depends on honest, informed scoring by your analysts.
        Inconsistent scoring across different evaluators can skew results. We recommend:</p>
    <ul>
        <li>Establishing clear definitions for each D level before scoring begins</li>
        <li>Having the same analyst or team score all techniques in a given run for consistency</li>
        <li>Re-evaluating D scores periodically as your detection capabilities evolve</li>
    </ul>
    <p>NDI also does not account for detection quality &mdash; a SIEM alert (D=2) that generates hundreds
        of false positives is counted the same as a well-tuned alert. Consider NDI a starting point for
        discussion rather than a definitive measurement of detection maturity.</p>

</template>

<script lang="ts">
import { defineComponent } from "vue";
declare const MathJax: { typeset: () => void }

export default defineComponent({
    data() {
        return {};
    },
    mounted() {
        MathJax.typeset()
    }
});
</script>

<style scoped>
h3 {
    @apply uppercase font-bold text-lg mt-3 mb-0
}

h4 {
    @apply uppercase font-bold
}

.detection-table {
    @apply w-full border-collapse text-sm
}

.detection-table th {
    @apply bg-ctid-navy text-white uppercase font-bold px-3 py-2 text-left
}

.detection-table td {
    @apply px-3 py-2 border border-gray-300
}

.detection-table tr:nth-child(even) td {
    @apply bg-gray-50
}

.weight-table {
    @apply w-full border-collapse text-sm
}

.weight-table th {
    @apply bg-ctid-navy text-white uppercase font-bold px-3 py-2 text-left
}

.weight-table td {
    @apply px-3 py-2 border border-gray-300
}

.weight-table tr:nth-child(even) td {
    @apply bg-gray-50
}

ul {
    @apply list-disc ml-6 mb-4
}

ol {
    @apply mb-4
}

ul p {
    @apply pl-4
}

a {
    @apply text-ctid-blue hover:underline
}

p {
    @apply mb-2
}
</style>
