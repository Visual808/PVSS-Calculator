#!/usr/bin/env python3
"""
Physical Security Vulnerability Scoring System
A GUI tool for scoring physical security and social engineering vulnerabilities
"""

import tkinter as tk
from tkinter import ttk, messagebox
import math

class PhysicalSecurityScoring:
    def __init__(self, root):
        self.root = root
        self.root.title("Physical Security Vulnerability Scoring System")
        self.root.geometry("900x900")
        self.root.resizable(True, True)
        
        # Variables for scoring and options storage
        self.vars = {}
        self.options_data = {}
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame with scrollbar
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="Physical Security Vulnerability Scoring System", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Create notebook for organized sections
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Base Metrics Tab
        base_frame = ttk.Frame(notebook)
        notebook.add(base_frame, text="Vulnerability Assessment")
        self.create_base_metrics(base_frame)
        
        # Impact Metrics Tab
        impact_frame = ttk.Frame(notebook)
        notebook.add(impact_frame, text="Potential Impact")
        self.create_impact_metrics(impact_frame)
        
        # Temporal Metrics Tab
        temporal_frame = ttk.Frame(notebook)
        notebook.add(temporal_frame, text="Current Status")
        self.create_temporal_metrics(temporal_frame)
        
        # Environmental Metrics Tab
        env_frame = ttk.Frame(notebook)
        notebook.add(env_frame, text="Facility Context")
        self.create_environmental_metrics(env_frame)
        
        # Results Tab
        results_frame = ttk.Frame(notebook)
        notebook.add(results_frame, text="Risk Assessment")
        self.create_results_section(results_frame)
        
        # Calculate button
        calc_frame = ttk.Frame(main_frame)
        calc_frame.pack(fill=tk.X, pady=(10, 0))
        
        calc_button = ttk.Button(calc_frame, text="Calculate Risk Score", 
                                command=self.calculate_score, style="Accent.TButton")
        calc_button.pack(side=tk.LEFT)
        
        clear_button = ttk.Button(calc_frame, text="Clear All", 
                                 command=self.clear_all)
        clear_button.pack(side=tk.LEFT, padx=(10, 0))
        
    def create_base_metrics(self, parent):
        # Scrollable frame
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Enable mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def _bind_to_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        def _unbind_from_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
        
        canvas.bind('<Enter>', _bind_to_mousewheel)
        canvas.bind('<Leave>', _unbind_from_mousewheel)
        
        # Physical Access Required
        self.create_metric_group(scrollable_frame, "Physical Access Level", "access_level", [
            ("Public Access", "Public", 0.95, "Accessible from public areas (lobbies, parking lots, exterior)"),
            ("Restricted Access", "Restricted", 0.75, "Requires basic authorization (employee areas, ID badge zones)"),
            ("Secure Access", "Secure", 0.50, "Requires specific clearance (server rooms, executive areas)"),
            ("High Security", "HighSecurity", 0.25, "Requires high-level clearance (vaults, critical infrastructure)")
        ])
        
        # Skill/Knowledge Required
        self.create_metric_group(scrollable_frame, "Skill Level Required", "skill_level", [
            ("None/Minimal", "None", 0.90, "No special skills needed (door propping, tailgating)"),
            ("Basic", "Basic", 0.70, "Basic knowledge or tools (lock picking, basic social engineering)"),
            ("Intermediate", "Intermediate", 0.50, "Specialized knowledge (alarm bypass, advanced social engineering)"),
            ("Expert", "Expert", 0.30, "Expert-level skills (sophisticated bypass techniques, insider knowledge)")
        ])
        
        # Time Required
        self.create_metric_group(scrollable_frame, "Time to Exploit", "time_required", [
            ("Immediate", "Immediate", 0.95, "Instant or under 1 minute"),
            ("Minutes", "Minutes", 0.80, "1-15 minutes required"),
            ("Extended", "Extended", 0.60, "15 minutes to 1 hour"),
            ("Prolonged", "Prolonged", 0.40, "Multiple hours or repeated visits required")
        ])
        
        # Tools/Equipment Required
        self.create_metric_group(scrollable_frame, "Tools/Equipment Required", "tools_required", [
            ("None", "None", 0.95, "No tools needed (social engineering, unsecured doors)"),
            ("Common Items", "Common", 0.80, "Everyday items (wedges, magnets, common tools)"),
            ("Basic Tools", "Basic", 0.65, "Basic security tools (bump keys, RFID cloners)"),
            ("Specialized Equipment", "Specialized", 0.45, "Professional equipment (thermal imaging, advanced electronics)"),
            ("Custom/Rare Equipment", "Custom", 0.25, "Custom-built or highly specialized equipment")
        ])
        
        # Detection Likelihood
        self.create_metric_group(scrollable_frame, "Detection Likelihood", "detection_likelihood", [
            ("Very Low", "VeryLow", 0.90, "Unlikely to be noticed (blind spots, no monitoring)"),
            ("Low", "Low", 0.75, "Low chance of detection (minimal monitoring)"),
            ("Medium", "Medium", 0.55, "Moderate chance of detection (basic monitoring)"),
            ("High", "High", 0.35, "High chance of detection (active monitoring, guards)"),
            ("Very High", "VeryHigh", 0.15, "Almost certain detection (multiple overlapping controls)")
        ])
        
        # Social Engineering Component
        self.create_metric_group(scrollable_frame, "Social Engineering Required", "social_engineering", [
            ("None", "None", 1.00, "No human interaction required"),
            ("Minimal", "Minimal", 0.85, "Basic interaction (asking for directions, casual conversation)"),
            ("Moderate", "Moderate", 0.70, "Deliberate deception (impersonation, pretexting)"),
            ("Extensive", "Extensive", 0.50, "Complex social engineering (multiple interactions, relationship building)")
        ])
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def create_impact_metrics(self, parent):
        # Scrollable frame
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Enable mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def _bind_to_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        def _unbind_from_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
        
        canvas.bind('<Enter>', _bind_to_mousewheel)
        canvas.bind('<Leave>', _unbind_from_mousewheel)
        
        # Impact Metrics
        ttk.Label(scrollable_frame, text="Potential Impact Assessment", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Physical Asset Impact
        self.create_metric_group(scrollable_frame, "Physical Asset Impact", "asset_impact", [
            ("Critical", "Critical", 0.85, "Access to critical infrastructure, cash, or irreplaceable assets"),
            ("High", "High", 0.65, "Access to valuable equipment or sensitive areas"),
            ("Medium", "Medium", 0.45, "Access to standard office areas or moderate-value assets"),
            ("Low", "Low", 0.25, "Access to low-value areas or assets"),
            ("Minimal", "Minimal", 0.10, "No significant physical asset exposure")
        ])
        
        # Information Access Impact
        self.create_metric_group(scrollable_frame, "Information Access Impact", "info_impact", [
            ("Critical", "Critical", 0.85, "Access to highly sensitive data (financial, personal, classified)"),
            ("High", "High", 0.65, "Access to confidential business information"),
            ("Medium", "Medium", 0.45, "Access to internal information or documents"),
            ("Low", "Low", 0.25, "Access to limited sensitive information"),
            ("Minimal", "Minimal", 0.10, "No significant information exposure")
        ])
        
        # Operational Impact
        self.create_metric_group(scrollable_frame, "Operational Impact", "operational_impact", [
            ("Critical", "Critical", 0.85, "Could halt critical operations or cause safety issues"),
            ("High", "High", 0.65, "Significant operational disruption"),
            ("Medium", "Medium", 0.45, "Moderate operational impact"),
            ("Low", "Low", 0.25, "Minor operational disruption"),
            ("Minimal", "Minimal", 0.10, "No significant operational impact")
        ])
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def create_temporal_metrics(self, parent):
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Enable mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def _bind_to_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        def _unbind_from_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
        
        canvas.bind('<Enter>', _bind_to_mousewheel)
        canvas.bind('<Leave>', _unbind_from_mousewheel)
        
        # Exploit Status
        self.create_metric_group(scrollable_frame, "Exploit Feasibility", "exploit_status", [
            ("Not Assessed", "NotAssessed", 1.00, "Use base assessment"),
            ("Confirmed", "Confirmed", 1.00, "Successfully demonstrated during assessment"),
            ("Highly Likely", "HighlyLikely", 0.95, "Very likely to succeed based on observations"),
            ("Probable", "Probable", 0.85, "Likely to succeed with reasonable effort"),
            ("Possible", "Possible", 0.70, "May succeed under right conditions"),
            ("Theoretical", "Theoretical", 0.50, "Theoretical vulnerability, untested")
        ])
        
        # Current Security Posture
        self.create_metric_group(scrollable_frame, "Current Security Measures", "security_posture", [
            ("Not Assessed", "NotAssessed", 1.00, "Use base assessment"),
            ("No Controls", "NoControls", 1.00, "No security measures in place"),
            ("Minimal Controls", "Minimal", 0.90, "Basic or ineffective security measures"),
            ("Some Controls", "Some", 0.75, "Some security measures but gaps exist"),
            ("Good Controls", "Good", 0.60, "Generally good security with minor weaknesses"),
            ("Strong Controls", "Strong", 0.40, "Strong security measures with rare vulnerabilities")
        ])
        
        # Remediation Availability
        self.create_metric_group(scrollable_frame, "Remediation Status", "remediation_status", [
            ("Not Assessed", "NotAssessed", 1.00, "Use base assessment"),
            ("No Solution", "NoSolution", 1.00, "No immediate solution available"),
            ("Workaround Available", "Workaround", 0.90, "Temporary workaround possible"),
            ("Partial Solution", "Partial", 0.80, "Partial solution reduces risk"),
            ("Solution Available", "Available", 0.70, "Complete solution exists but not implemented"),
            ("Solution Implemented", "Implemented", 0.50, "Solution has been implemented")
        ])
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def create_environmental_metrics(self, parent):
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Enable mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def _bind_to_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        def _unbind_from_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
        
        canvas.bind('<Enter>', _bind_to_mousewheel)
        canvas.bind('<Leave>', _unbind_from_mousewheel)
        
        ttk.Label(scrollable_frame, text="Facility-Specific Risk Factors", 
                 font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Facility Type
        self.create_metric_group(scrollable_frame, "Facility Type", "facility_type", [
            ("Not Specified", "NotSpecified", 1.00, "Use base assessment"),
            ("Level A", "Level A", 1.5, "Enhanced Protection Area; Highly Restrictive"),
            ("Level B", "Level B", 1.25, "Protected Area; General Operations"),
            ("Level C", "Level C", 1, "Controlled & Restricted Access"),
            ("Level D", "Level D", 0.75, "Uncontrolled & Restricted Access"),
            ("Level E", "Level E", 0.5, "Uncontrolled & Unrestricted Access")
        ])
        
        # Threat Level
        self.create_metric_group(scrollable_frame, "Local Threat Environment", "threat_level", [
            ("Not Specified", "NotSpecified", 1.00, "Use base assessment"),
            ("High", "High", 1.50, "High crime rates, known security issues"),
            ("Moderate", "Moderate", 1.25, "Average crime rates for area type"),
            ("Low", "Low", 0.85, "Low crime rates, generally safe area"),
            ("Secure Location", "Secure", 0.70, "Gated community, secure business park")
        ])
        
        # Business Criticality
        self.create_metric_group(scrollable_frame, "Business Criticality", "business_criticality", [
            ("Not Specified", "NotSpecified", 1.00, "Use base assessment"),
            ("Mission Critical", "MissionCritical", 1.75, "Essential to business operations or public safety"),
            ("Business Critical", "BusinessCritical", 1.50, "Important to business operations"),
            ("Important", "Important", 1.25, "Significant but not critical"),
            ("Standard", "Standard", 1.00, "Normal business importance"),
            ("Low Impact", "LowImpact", 0.75, "Minimal impact to business operations")
        ])
        
        # Operating Hours
        self.create_metric_group(scrollable_frame, "Operating Hours Risk", "operating_hours", [
            ("Not Specified", "NotSpecified", 1.00, "Use base assessment"),
            ("24/7 Operations", "Always", 0.80, "Always staffed and active"),
            ("Extended Hours", "Extended", 0.90, "Long hours with some unstaffed periods"),
            ("Business Hours", "Business", 1.00, "Standard business hours"),
            ("Limited Hours", "Limited", 1.15, "Short operating hours, often unattended"),
            ("Rarely Occupied", "Rarely", 1.30, "Infrequently staffed or visited")
        ])
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def create_results_section(self, parent):
        # Results display
        self.results_text = tk.Text(parent, height=20, wrap=tk.WORD, font=("Courier", 10))
        results_scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=results_scrollbar.set)
        
        self.results_text.pack(side="left", fill="both", expand=True)
        results_scrollbar.pack(side="right", fill="y")
        
        # Export button frame
        export_frame = ttk.Frame(parent)
        export_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(export_frame, text="Copy Results", 
                  command=self.copy_results).pack(side=tk.LEFT)
        
    def create_metric_group(self, parent, title, var_name, options):
        # Group frame with fixed minimum width
        group_frame = ttk.LabelFrame(parent, text=title, padding=10)
        group_frame.pack(fill=tk.X, pady=5)
        
        # Variable for this metric (stores the index)
        self.vars[var_name] = tk.IntVar()
        self.options_data[var_name] = options
        
        # Create a frame for the slider and labels with fixed width
        slider_frame = ttk.Frame(group_frame, width=800)
        slider_frame.pack(fill=tk.X, pady=5)
        slider_frame.pack_propagate(False)  # Prevent frame from shrinking
        
        # Current selection label with fixed width
        selection_label = ttk.Label(slider_frame, text="", font=("Arial", 10, "bold"), 
                                   anchor="center")
        selection_label.pack(pady=(0, 5), fill=tk.X)
        
        # Slider
        slider = ttk.Scale(slider_frame, from_=0, to=len(options)-1, 
                          orient=tk.HORIZONTAL, variable=self.vars[var_name])
        slider.pack(fill=tk.X, pady=5, padx=20)
        
        # Description label with fixed width and no wrapping
        desc_label = ttk.Label(slider_frame, text="", font=("Arial", 9), 
                              foreground="gray", anchor="center")
        desc_label.pack(pady=(5, 0), fill=tk.X)
        
        # Function to update labels when slider changes
        def update_labels(val):
            try:
                index = int(float(val))
                if 0 <= index < len(options):
                    option_text, value, score, description = options[index]
                    selection_label.config(text=f"{option_text} (Score: {score})")
                    desc_label.config(text=description)
            except (ValueError, IndexError):
                pass
        
        # Bind the update function to slider changes
        slider.config(command=update_labels)
        
        # Initialize with first option
        update_labels(0)
        
    def calculate_score(self):
        try:
            # Get metric values - convert slider positions to actual values
            metrics = {}
            for var_name, var in self.vars.items():
                slider_index = var.get()
                options = self.options_data[var_name]
                
                if 0 <= slider_index < len(options):
                    _, value, _, _ = options[slider_index]
                    metrics[var_name] = value
                else:
                    messagebox.showwarning("Invalid Selection", 
                                         f"Invalid selection for {var_name.replace('_', ' ').title()}")
                    return
            
            # Calculate base score
            base_score = self.calculate_base_score(metrics)
            
            # Calculate temporal score
            temporal_score = self.calculate_temporal_score(base_score, metrics)
            
            # Calculate environmental score
            environmental_score = self.calculate_environmental_score(temporal_score, metrics)
            
            # Display results
            self.display_results(base_score, temporal_score, environmental_score, metrics)
            
        except Exception as e:
            messagebox.showerror("Calculation Error", f"Error calculating score: {str(e)}")
    
    def calculate_base_score(self, metrics):
        # Get exploitability factors
        exploitability_metrics = {
            "access_level": {"Public": 0.95, "Restricted": 0.75, "Secure": 0.50, "HighSecurity": 0.25},
            "skill_level": {"None": 0.90, "Basic": 0.70, "Intermediate": 0.50, "Expert": 0.30},
            "time_required": {"Immediate": 0.95, "Minutes": 0.80, "Extended": 0.60, "Prolonged": 0.40},
            "tools_required": {"None": 0.95, "Common": 0.80, "Basic": 0.65, "Specialized": 0.45, "Custom": 0.25},
            "detection_likelihood": {"VeryLow": 0.90, "Low": 0.75, "Medium": 0.55, "High": 0.35, "VeryHigh": 0.15},
            "social_engineering": {"None": 1.00, "Minimal": 0.85, "Moderate": 0.70, "Extensive": 0.50}
        }
        
        # Get impact factors
        impact_metrics = {
            "asset_impact": {"Critical": 0.85, "High": 0.65, "Medium": 0.45, "Low": 0.25, "Minimal": 0.10},
            "info_impact": {"Critical": 0.85, "High": 0.65, "Medium": 0.45, "Low": 0.25, "Minimal": 0.10},
            "operational_impact": {"Critical": 0.85, "High": 0.65, "Medium": 0.45, "Low": 0.25, "Minimal": 0.10}
        }
        
        # Calculate exploitability (weighted average)
        exploitability_score = 1.0
        for metric, values in exploitability_metrics.items():
            exploitability_score *= values[metrics[metric]]
        
        # Normalize exploitability to 0-10 scale
        exploitability = 10.0 * exploitability_score
        
        # Calculate impact (take the maximum of the three impact areas)
        impact_values = []
        for metric, values in impact_metrics.items():
            impact_values.append(values[metrics[metric]])
        
        # Use weighted average of impacts, giving more weight to highest impact
        impact_values.sort(reverse=True)
        impact = (impact_values[0] * 0.6 + impact_values[1] * 0.3 + impact_values[2] * 0.1) * 10.0
        
        # Calculate base score (combination of exploitability and impact)
        if impact <= 0:
            base_score = 0
        else:
            # Modified formula for physical security
            base_score = min(10.0, (exploitability * 0.6 + impact * 0.4))
        
        return round(base_score, 1)
    
    def calculate_temporal_score(self, base_score, metrics):
        # Temporal metric values
        temporal_metrics = {
            "exploit_status": {"NotAssessed": 1.00, "Confirmed": 1.00, "HighlyLikely": 0.95, 
                              "Probable": 0.85, "Possible": 0.70, "Theoretical": 0.50},
            "security_posture": {"NotAssessed": 1.00, "NoControls": 1.00, "Minimal": 0.90,
                               "Some": 0.75, "Good": 0.60, "Strong": 0.40},
            "remediation_status": {"NotAssessed": 1.00, "NoSolution": 1.00, "Workaround": 0.90,
                                 "Partial": 0.80, "Available": 0.70, "Implemented": 0.50}
        }
        
        # Apply temporal modifiers
        temporal_modifier = 1.0
        for metric, values in temporal_metrics.items():
            temporal_modifier *= values[metrics[metric]]
        
        temporal_score = base_score * temporal_modifier
        return round(temporal_score, 1)
    
    def calculate_environmental_score(self, temporal_score, metrics):
        # Environmental modifiers
        env_metrics = {
            "facility_type": {"NotSpecified": 1.00, "Level A": 1.5, "Level B": 1.25, 
                             "Level C": 1.0, "Level D": 0.75, "Level E": 0.5},
            "threat_level": {"NotSpecified": 1.00, "High": 1.50, "Moderate": 1.25, 
                            "Low": 0.85, "Secure": 0.70},
            "business_criticality": {"NotSpecified": 1.00, "MissionCritical": 1.75, "BusinessCritical": 1.50,
                                   "Important": 1.25, "Standard": 1.00, "LowImpact": 0.75},
            "operating_hours": {"NotSpecified": 1.00, "Always": 0.80, "Extended": 0.90,
                              "Business": 1.00, "Limited": 1.15, "Rarely": 1.30}
        }
        
        # Apply environmental modifiers
        env_modifier = 1.0
        for metric, values in env_metrics.items():
            env_modifier *= values[metrics[metric]]
        
        environmental_score = min(10.0, temporal_score * env_modifier)
        return round(environmental_score, 1)
    
    def display_results(self, base_score, temporal_score, environmental_score, metrics):
        self.results_text.delete(1.0, tk.END)
        
        # Create severity rating
        def get_severity(score):
            if score == 0.0:
                return "None"
            elif score <= 2.9:
                return "Low"
            elif score <= 5.9:
                return "Medium"
            elif score <= 7.9:
                return "High"
            else:
                return "Critical"
        
        # Create priority recommendations
        def get_priority(score):
            if score >= 8.0:
                return "IMMEDIATE - Address within 24-48 hours"
            elif score >= 6.0:
                return "HIGH - Address within 1-2 weeks"
            elif score >= 4.0:
                return "MEDIUM - Address within 1-3 months"
            elif score >= 2.0:
                return "LOW - Address during next review cycle"
            else:
                return "INFORMATIONAL - Monitor and reassess"
        
        results = f"""
PHYSICAL SECURITY VULNERABILITY ASSESSMENT
==========================================

RISK SCORES:
Base Score: {base_score}/10.0 ({get_severity(base_score)})
Temporal Score: {temporal_score}/10.0 ({get_severity(temporal_score)})
Environmental Score: {environmental_score}/10.0 ({get_severity(environmental_score)})

PRIORITY: {get_priority(environmental_score)}

VULNERABILITY DETAILS:
=====================

Physical Access & Exploitability:
- Access Level Required: {metrics['access_level']}
- Skill Level Required: {metrics['skill_level']}
- Time to Exploit: {metrics['time_required']}
- Tools/Equipment Required: {metrics['tools_required']}
- Detection Likelihood: {metrics['detection_likelihood']}
- Social Engineering Required: {metrics['social_engineering']}

Potential Impact:
- Physical Asset Impact: {metrics['asset_impact']}
- Information Access Impact: {metrics['info_impact']}
- Operational Impact: {metrics['operational_impact']}

Current Status:
- Exploit Feasibility: {metrics['exploit_status']}
- Current Security Measures: {metrics['security_posture']}
- Remediation Status: {metrics['remediation_status']}

Facility Context:
- Facility Type: {metrics['facility_type']}
- Local Threat Environment: {metrics['threat_level']}
- Business Criticality: {metrics['business_criticality']}
- Operating Hours Risk: {metrics['operating_hours']}

RISK LEVEL DEFINITIONS:
======================
Critical (8.0-10.0): Severe risk requiring immediate action
High (6.0-7.9): Significant risk requiring prompt attention
Medium (4.0-5.9): Moderate risk requiring planned remediation
Low (2.0-3.9): Minor risk requiring monitoring
Informational (0.0-1.9): Minimal risk

RECOMMENDED ACTIONS:
===================
"""
        
        # Add specific recommendations based on score and metrics
        if environmental_score >= 8.0:
            results += """- EMERGENCY RESPONSE: Implement immediate countermeasures
- Assign dedicated security personnel if needed
- Review and test incident response procedures
- Consider temporary additional security measures
- Escalate to senior management immediately
"""
        elif environmental_score >= 6.0:
            results += """- HIGH PRIORITY: Schedule remediation within 1-2 weeks
- Assign specific personnel responsibility
- Implement interim security measures if needed
- Set firm completion timeline
- Regular progress monitoring
"""
        elif environmental_score >= 4.0:
            results += """- MEDIUM PRIORITY: Include in quarterly security improvements
- Assign to security improvement backlog
- Consider during next budget cycle
- Monitor for changes in threat landscape
"""
        elif environmental_score >= 2.0:
            results += """- LOW PRIORITY: Address during annual security review
- Document for future reference
- Monitor for environmental changes
- Consider cost-effective improvements
"""
        else:
            results += """- INFORMATIONAL: Document and periodically reassess
- No immediate action required
- Monitor for changes in facility or threats
"""
        
        # Add specific recommendations based on vulnerability type
        if metrics['access_level'] in ['Public', 'Restricted']:
            results += "\n- Consider additional access controls or barriers"
        if metrics['detection_likelihood'] in ['VeryLow', 'Low']:
            results += "\n- Enhance monitoring and detection capabilities"
        if metrics['social_engineering'] in ['Moderate', 'Extensive']:
            results += "\n- Implement security awareness training"
        if metrics['security_posture'] in ['NoControls', 'Minimal']:
            results += "\n- Implement basic security controls"
        
        self.results_text.insert(tk.END, results)
    
    def copy_results(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.results_text.get(1.0, tk.END))
        messagebox.showinfo("Copied", "Results copied to clipboard")
    
    def clear_all(self):
        for var in self.vars.values():
            var.set(0)  # Reset sliders to first position
        self.results_text.delete(1.0, tk.END)

def main():
    root = tk.Tk()
    app = PhysicalSecurityScoring(root)
    root.mainloop()

if __name__ == "__main__":
    main()
