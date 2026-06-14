const ExcelJS = require("exceljs");
const fs = require("fs");
const SOURCE_FILE = "src/data/Calculator.xlsx";
const DESTINATION_FILE = "src/data/Techniques.json";

(async function () {
  const wb = new ExcelJS.Workbook();
  // initialize new list for techniques
  const techniques = [];
  const subtechniques = [];
  // read from techniques tab first to get the technique metadata (ID, name, etc.)
  await wb.xlsx.readFile(SOURCE_FILE);
  console.log("Reading from Calculator spreadsheet...");
  const techniqueList = wb.getWorksheet("techniques");
  techniqueList.eachRow((r) => {
    if (r.number > 1) {
      const t = {
        tid: r.getCell(1).value,
        name: r.getCell(2).value,
        description: r.getCell(3).value,
        url: r.getCell(4).hyperlink
          ? r.getCell(4).hyperlink
          : r.getCell(4).value,
        detection: r.getCell(9).value,
        platforms: r.getCell(10).value ? r.getCell(10).value.toString().split(", ") : [],
        data_sources: r.getCell(11).value
          ? r.getCell(11).value.toString().split(", ")
          : [],
        is_subtechnique: Boolean(r.getCell(12).value),
        supertechnique: r.getCell(13).value ? r.getCell(13).value.toString().trim() : null,
        subtechniques: [],
        mitigations: [],
      };
      if (t.is_subtechnique) {
        subtechniques.push(t);
      }
      techniques.push(t);
    }
  });

  console.log("Parsed technique metadata from Techniques tab ");

  // // read from mitigations tab to get a list of all mitigations
  const mitigations = [];
  const mitigationSheet = wb.getWorksheet("mitigations");
  console.log("Parsing mitigation objects... ");
  mitigationSheet.eachRow((r) => {
    if (r.number > 1) {
      const m = {
        mid: r.getCell(1).value,
        name: r.getCell(3).value,
        description: r.getCell(4).value,
        url: r.getCell(5).hyperlink,
      };
      mitigations.push(m);
    }
  });
  console.log("Parsing relationships... ");
  // read from relationships tab to assign mitigations to techniques
  const relationshipSheet = wb.getWorksheet("relationships");
  relationshipSheet.eachRow((r) => {
    if (
      r.number > 1 &&
      r.getCell(1).value &&
      r.getCell(1).value.charAt(0) === "M"
    ) {
      const mitigation = mitigations.find((m) => m.mid === r.getCell(1).value);
      if (r.getCell(6).value.includes(".")) {
        const subtechnique = subtechniques.find(
          (t) => t.tid === r.getCell(6).value
        );
        if (subtechnique) {
          subtechnique.mitigations.push(mitigation);
        }
      } else {
        const technique = techniques.find((t) => t.tid === r.getCell(6).value);
        if (technique) {
          technique.mitigations.push(mitigation);
        }
      }
    }
  });
  console.log("Parsed relationships");
  // add subtechniques to techniques
  console.log("Parsing subtechniques...");
  for (const subtechnique of subtechniques) {
    const technique = techniques.find(
      (t) => t.tid === subtechnique.supertechnique
    );
    const s = {
      tid: subtechnique.tid,
      name: subtechnique.name,
      url: subtechnique.url,
      description: subtechnique.description,
      detection: subtechnique.detection,
      mitigations: subtechnique.mitigations,
    };
    technique.subtechniques.push(s);
  }
  console.log("Parsed subtechniques");
  // helper to safely extract numeric value (plain number or formula result)
  function getNumeric(cell) {
    const v = cell.value;
    if (v === null || v === undefined) return null;
    if (typeof v === 'number') return v;
    if (typeof v === 'object' && v !== null && 'result' in v) return v.result;
    const parsed = parseFloat(v);
    return isNaN(parsed) ? null : parsed;
  }
  // read from the methodology tab to add scores to the technique objects
  const scoreList = wb.getWorksheet("Methodology");
  scoreList.eachRow((r) => {
    const id = r.getCell(3).value;
    if (id) {
      const technique = techniques.find((t) => t.tid == id);
      if (technique && technique.tid) {
        technique.cumulative_score = getNumeric(r.getCell("B"));
        technique.adjusted_score = technique.cumulative_score;
        technique.has_car = !!r.getCell("N").value;
        technique.has_sigma = !!r.getCell("O").value;
        technique.has_es_siem = !!r.getCell("P").value;
        technique.has_splunk = !!r.getCell("Q").value;

        technique.cis_controls = r.getCell("R").value
          ? r
              .getCell("R")
              .value.toString()
              .split(/\s*,\s*/)
          : [];
        technique.nist_controls = r.getCell("T").value
          ? r.getCell("T").value.toString().split(",")
          : [];

        technique.process_coverage = !!getNumeric(r.getCell(31));
        technique.network_coverage = !!getNumeric(r.getCell(33));
        technique.file_coverage = !!getNumeric(r.getCell(35));
        technique.cloud_coverage = !!getNumeric(r.getCell(37));
        technique.hardware_coverage = !!getNumeric(r.getCell(39));

        // NDI scoring fields: weight (W), detection_level (D), ndi_score (W×D)
        technique.weight = getNumeric(r.getCell(40)) || 2;   // column AN — default 2 if missing
        technique.detection_level = getNumeric(r.getCell(42)) || 0;  // column AP — default 0
        technique.ndi_score = getNumeric(r.getCell(44)) || 0;  // column AR — default 0

        technique.actionability_score = {
          combined_score: getNumeric(r.getCell(22)),
          mitigation_score: getNumeric(r.getCell(25)),
          detection_score: getNumeric(r.getCell(28)),
        };
        technique.choke_point_score = getNumeric(r.getCell(8));
        technique.prevalence_score = getNumeric(r.getCell(13));
      }
    }
  });
  console.log("Parsed scores from Methodology page");
  // export technique list to JSON
  const str = JSON.stringify(techniques, null, 4);
  fs.writeFile(DESTINATION_FILE, str, (error) => {
    if (error) {
      console.error(error);
      throw error;
    }
  });
  console.log("Export technique data to Techniques.json");
})();
