export interface Technique
  extends TechniqueBase,
    TechniqueCoverage,
    TechniqueScores {
  cumulative_score: number;
  adjusted_score: number;
  tactics: Array<string>;
  /** NDI Weight (W): 1=low (discovery/recon), 2=medium (collection), 3=critical (execution/persistence/defense-evasion/etc.) */
  weight: number;
  /** NDI Detection Level (D): null=not set, 0=no logs, 1=raw logs, 2=SIEM alert, 3=prevention */
  detection_level: number | null;
  /** NDI Score = weight × detection_level (contribution to overall NDI numerator) */
  ndi_score: number;
  is_subtechnique: boolean;
  supertechnique: string | null;
  cis_controls: Array<string>;
  nist_controls: Array<string>;
  platforms: Array<string>;
  data_sources: Array<string>;
  has_car: boolean;
  has_sigma: boolean;
  has_es_siem: boolean;
  has_splunk: boolean;
}
export interface ExportedTechnique extends Omit<TechniqueBase, 'detection'>, TechniqueScores {
  rank: number;
  score: number;
  detection_level: number | null;
}
export interface TechniqueBase {
  tid: string;
  name: string;
  description: string;
  url: string;
  detection: string;
  subtechniques: Array<Subtechnique>;
  mitigations: Array<Mitigation>;
}
export interface Subtechnique {
  tid: string;
  name: string;
  description: string;
  url: string;
  detection: string;
  mitigations: Array<Mitigation>;
  /** NDI Weight (W): 1=low, 2=medium, 3=critical */
  weight: number;
  /** NDI Detection Level (D): null=not set, 0=no logs, 1=raw logs, 2=SIEM alert, 3=prevention */
  detection_level: number | null;
  /** NDI Score = weight × detection_level */
  ndi_score: number;
}
export interface Mitigation {
  mid: string;
  name: string;
  description: string;
  url: string;
}

export interface TechniqueScores {
  process_score: number;
  network_score: number;
  file_score: number;
  cloud_score: number;
  hardware_score: number;
  actionability_score: {
    combined_score: number;
    mitigation_score: number;
    detection_score: number;
  };
  choke_point_score: number;
  prevalence_score: number;
}

export interface TechniqueCoverage {
  process_coverage: boolean;
  network_coverage: boolean;
  file_coverage: boolean;
  cloud_coverage: boolean;
  hardware_coverage: boolean;
}
