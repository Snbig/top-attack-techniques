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
    <p>Every technique is assigned a weight from 1 to 3 based on its overall importance in your ranked list.
        The weight reflects the technique's relative standing after combining its actionability score, choke
        point score, and prevalence score, all adjusted for your organization's monitoring levels
        (Network, Process, File, Cloud, Hardware).</p>
    <p>Weight is assigned using a <strong>tertile-based distribution</strong>:</p>
    <ul>
        <li><strong>W = 1</strong> &mdash; Bottom third (least critical, typically discovery/reconnaissance
            techniques)</li>
        <li><strong>W = 2</strong> &mdash; Middle third (moderate criticality, e.g. collection techniques)
        </li>
        <li><strong>W = 3</strong> &mdash; Top third (most critical, e.g. execution, persistence, and
            defense evasion techniques)</li>
    </ul>
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
            high-weight (W=3) techniques first, as they have the greatest impact on the overall score.
        </li>
        <li><strong>NDI &lt; 40%</strong> &mdash; Significant gaps. Use the per-technique breakdown
            to identify which critical techniques lack detection coverage and build a remediation plan.
        </li>
    </ul>
    <p>Because NDI weights techniques by their importance, improving detection for a single W=3 technique
        has three times the impact of improving a W=1 technique. This makes NDI an effective tool for
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
