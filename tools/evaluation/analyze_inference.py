#!/usr/bin/env python3
"""
Inference result analysis tool
Analyzes attack detection performance including confusion matrix, KPI metrics and risk visualization

Usage:
    python analyze_inference.py <csv_file> <attacker_range> [output_dir]

Examples:
    python analyze_inference.py inference_20251225_092222.csv 46-50
    python analyze_inference.py inference_20251225_092222.csv 46-50 /path/to/output
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import json
import argparse
import sys
from typing import Tuple, Dict, Any


class InferenceAnalyzer:
    """Inference result analyzer"""
    
    def __init__(self, csv_path: str, attacker_range: str):
        """
        Initialize analyzer
        
        Args:
            csv_path: Path to inference result CSV file
            attacker_range: Attacker range, format "start-end", e.g., "46-50"
        """
        # Read CSV and take the last record per user (final state)
        df_all = pd.read_csv(csv_path)
        # Remove leading/trailing spaces from column names
        df_all.columns = df_all.columns.str.strip()
        self.df = df_all.groupby('supi').tail(1).reset_index(drop=True)
        self.csv_path = Path(csv_path)
        self.attacker_range = attacker_range
        self.metrics = {}
        
        # Parse attacker range
        self.attacker_ids = self._parse_attacker_range(attacker_range)
        
        # Create ground truth labels
        self._create_ground_truth_labels()
        
    def _parse_attacker_range(self, range_str: str) -> set:
        """Parse attacker range, e.g., "46-50" -> {46, 47, 48, 49, 50}"""
        start, end = map(int, range_str.split('-'))
        return set(range(start, end + 1))
    
    def _create_ground_truth_labels(self):
        """Create ground truth labels based on IMSI"""
        def extract_ue_id(imsi):
            """Extract UE ID from IMSI (last 2-3 digits)"""
            # imsi-208930000000046 -> 46
            # imsi-208930000000002 -> 2
            parts = imsi.split('-')
            if len(parts) > 1:
                try:
                    full_num = int(parts[-1])
                    # Take last 2-3 digits (support range 1-999)
                    ue_id = full_num % 1000
                    return ue_id
                except:
                    return None
            return None
        
        self.df['ue_id'] = self.df['supi'].apply(extract_ue_id)
        self.df['is_attacker'] = self.df['ue_id'].isin(self.attacker_ids)
    
    def _calculate_confusion_matrix(self) -> Dict[str, int]:
        """Calculate confusion matrix"""
        # True labels: is_attacker
        # Predicted labels: is_blocked or attack_detected
        y_true = self.df['is_attacker'].astype(int)
        
        # Convert string boolean values to actual booleans
        # Handle spaces in values: ' false ', ' true ', 'false', 'true', '1', '0'
        is_blocked = self.df['is_blocked'].astype(str).str.strip().str.lower().isin(['true', '1', 'yes'])
        attack_detected = self.df['attack_detected'].astype(str).str.strip().str.lower().isin(['true', '1', 'yes'])
        
        y_pred = (is_blocked | attack_detected).astype(int)
        
        tp = np.sum((y_true == 1) & (y_pred == 1))
        fp = np.sum((y_true == 0) & (y_pred == 1))
        tn = np.sum((y_true == 0) & (y_pred == 0))
        fn = np.sum((y_true == 1) & (y_pred == 0))
        
        return {
            'TP': int(tp),
            'FP': int(fp),
            'TN': int(tn),
            'FN': int(fn),
            'Total': len(self.df)
        }
    
    def _calculate_metrics(self, cm: Dict[str, int]) -> Dict[str, float]:
        """Calculate key performance indicators based on confusion matrix"""
        tp = cm['TP']
        fp = cm['FP']
        tn = cm['TN']
        fn = cm['FN']
        
        metrics = {}
        
        # Precision = TP / (TP + FP)
        metrics['precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        
        # Recall = TP / (TP + FN)
        metrics['recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        
        # F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
        if metrics['precision'] + metrics['recall'] > 0:
            metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / \
                                 (metrics['precision'] + metrics['recall'])
        else:
            metrics['f1_score'] = 0.0
        
        # FPR = FP / (TN + FP)
        metrics['fpr'] = fp / (tn + fp) if (tn + fp) > 0 else 0.0
        
        # Specificity = TN / (TN + FP)
        metrics['specificity'] = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        
        # Accuracy = (TP + TN) / (TP + FP + TN + FN)
        total = tp + fp + tn + fn
        metrics['accuracy'] = (tp + tn) / total if total > 0 else 0.0
        
        return metrics
    
    def analyze(self):
        """Execute complete analysis"""
        print(f"Analyzing inference results...")
        print(f"CSV File: {self.csv_path}")
        print(f"Attacker Range: {self.attacker_range}")
        print(f"Total Users (deduplicated): {len(self.df)}")
        print(f"Total Attackers: {sum(self.df['is_attacker'])}")
        print(f"Total Normal Users: {sum(~self.df['is_attacker'])}\n")
        
        # Calculate confusion matrix
        cm = self._calculate_confusion_matrix()
        self.metrics['confusion_matrix'] = cm
        
        # Calculate KPI
        kpi = self._calculate_metrics(cm)
        self.metrics['kpi'] = kpi
        
        # Generate report
        self._print_confusion_matrix(cm)
        self._print_kpi(kpi)
        
        return cm, kpi
    
    def _print_confusion_matrix(self, cm: Dict[str, int]):
        """Print confusion matrix report"""
        print("=" * 60)
        print("Confusion Matrix")
        print("=" * 60)
        print(f"True Positive (TP)   : {cm['TP']:6d}  (Attackers correctly detected)")
        print(f"False Positive (FP)  : {cm['FP']:6d}  (Normal users misclassified)")
        print(f"True Negative (TN)   : {cm['TN']:6d}  (Normal users correctly identified)")
        print(f"False Negative (FN)  : {cm['FN']:6d}  (Attackers missed)")
        print(f"{'-' * 60}")
        print(f"{'Total':18s} : {cm['Total']:6d}")
        print()
    
    def _print_kpi(self, kpi: Dict[str, float]):
        """Print KPI report"""
        print("=" * 60)
        print("Key Performance Indicators")
        print("=" * 60)
        print(f"Precision              : {kpi['precision']:.4f} ({kpi['precision']*100:.2f}%)")
        print(f"  Formula: TP / (TP + FP)")
        print(f"  Meaning: Of predicted attacks, how many are true attacks")
        print()
        
        print(f"Recall                 : {kpi['recall']:.4f} ({kpi['recall']*100:.2f}%)")
        print(f"  Formula: TP / (TP + FN)")
        print(f"  Meaning: Of all attackers, how many were caught")
        print()
        
        print(f"F1-Score               : {kpi['f1_score']:.4f}")
        print(f"  Formula: 2 × (Precision × Recall) / (Precision + Recall)")
        print(f"  Meaning: Combined metric balancing precision and recall")
        print()
        
        print(f"False Positive Rate    : {kpi['fpr']:.4f} ({kpi['fpr']*100:.4f}%)")
        print(f"  Formula: FP / (TN + FP)")
        print(f"  Meaning: Proportion of normal users incorrectly blocked")
        print()
        
        print(f"Specificity            : {kpi['specificity']:.4f} ({kpi['specificity']*100:.2f}%)")
        print(f"  Formula: TN / (TN + FP)")
        print(f"  Meaning: Proportion of normal users correctly identified")
        print()
        
        print(f"Accuracy               : {kpi['accuracy']:.4f} ({kpi['accuracy']*100:.2f}%)")
        print(f"  Formula: (TP + TN) / Total")
        print()
    
    def plot_confusion_matrix(self, output_path: Path = None):
        """繪製混淆矩陣熱力圖"""
        cm = self.metrics['confusion_matrix']
        
        # 創建混淆矩陣陣列
        cm_array = np.array([
            [cm['TN'], cm['FP']],
            [cm['FN'], cm['TP']]
        ])
        
        # 標準化以顯示百分比
        cm_percent = cm_array.astype('float') / cm_array.sum() * 100
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        sns.heatmap(
            cm_array,
            annot=True,
            fmt='d',
            cmap='Blues',
            cbar=True,
            xticklabels=['Normal', 'Attack'],
            yticklabels=['Normal', 'Attack'],
            ax=ax,
            cbar_kws={'label': 'Sample Count'},
            annot_kws={'size': 14, 'weight': 'bold'}
        )
        
        ax.set_xlabel('Predicted Label', fontsize=12, weight='bold')
        ax.set_ylabel('True Label', fontsize=12, weight='bold')
        ax.set_title(f'Confusion Matrix - Attackers: {self.attacker_range}', 
                    fontsize=14, weight='bold', pad=20)
        
        # Add metrics text
        kpi = self.metrics['kpi']
        textstr = f'Precision: {kpi["precision"]:.2%}\nRecall: {kpi["recall"]:.2%}\nF1: {kpi["f1_score"]:.4f}'
        ax.text(2.5, -0.3, textstr, transform=ax.transData,
               fontsize=10, verticalalignment='top',
               bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            print(f"Confusion matrix saved: {output_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_risk_accumulation(self, output_path: Path = None):
        """Plot risk distribution visualization"""
        # Show risk distribution
        fig, ax = plt.subplots(figsize=(14, 8))
        
        # Separate attackers and normal users
        attackers = self.df[self.df['is_attacker']].copy()
        normal_users = self.df[~self.df['is_attacker']].copy()
        
        # Sort by user ID for visualization
        attackers = attackers.sort_values('ue_id')
        normal_users = normal_users.sort_values('ue_id')
        
        # Plot risk distribution
        ax.scatter(range(len(normal_users)), normal_users['risk_score'], 
                  alpha=0.6, s=30, label='Normal Users', color='green')
        ax.scatter(range(len(normal_users), len(normal_users) + len(attackers)), 
                  attackers['risk_score'], alpha=0.8, s=100, 
                  label=f'Attackers ({self.attacker_range})', color='red', marker='^')
        
        # Add average lines
        normal_avg = normal_users['risk_score'].mean()
        attacker_avg = attackers['risk_score'].mean()
        
        ax.axhline(y=normal_avg, color='green', linestyle='--', linewidth=2, 
                  alpha=0.7, label=f'Normal Avg: {normal_avg:.2f}')
        ax.axhline(y=attacker_avg, color='red', linestyle='--', linewidth=2, 
                  alpha=0.7, label=f'Attacker Avg: {attacker_avg:.2f}')
        
        ax.set_xlabel('User Index', fontsize=12, weight='bold')
        ax.set_ylabel('Risk Score [0-100]', fontsize=12, weight='bold')
        ax.set_title(f'Risk Score Distribution - Attackers: {self.attacker_range}', 
                    fontsize=14, weight='bold', pad=20)
        ax.set_ylim(-5, 105)
        ax.grid(True, alpha=0.3)
        ax.legend(loc='upper left', fontsize=10)
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            print(f"Risk distribution plot saved: {output_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_risk_progression(self, output_path: Path = None):
        """Plot risk progression trend graph"""
        fig, ax = plt.subplots(figsize=(14, 8))
        
        # Get attackers and normal users risk scores
        attackers = self.df[self.df['is_attacker']].sort_values('risk_score')
        normal_users = self.df[~self.df['is_attacker']].sort_values('risk_score')
        
        # Plot line graph
        ax.plot(range(len(normal_users)), normal_users['risk_score'].values, 
               color='green', linewidth=2, marker='o', markersize=3, 
               label='Normal Users', alpha=0.7)
        
        ax.plot(range(len(normal_users), len(normal_users) + len(attackers)), 
               attackers['risk_score'].values, color='red', linewidth=2.5, 
               marker='^', markersize=5, label=f'Attackers ({self.attacker_range})', alpha=0.8)
        
        # Add shaded regions
        ax.axvspan(0, len(normal_users), alpha=0.1, color='green', label='Normal User Region')
        ax.axvspan(len(normal_users), len(normal_users) + len(attackers), 
                  alpha=0.1, color='red', label='Attacker Region')
        
        ax.set_xlabel('Request Order', fontsize=12, weight='bold')
        ax.set_ylabel('Risk Score [0-100]', fontsize=12, weight='bold')
        ax.set_title(f'Risk Progression Trend - Attackers: {self.attacker_range}\n' + 
                    '(Shows how system risk assessment evolves across users)', 
                    fontsize=14, weight='bold', pad=20)
        ax.set_ylim(-5, 105)
        ax.grid(True, alpha=0.3, axis='y')
        ax.legend(loc='upper left', fontsize=10)
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            print(f"Risk progression plot saved: {output_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_roc_curve(self, output_path: Path = None):
        """Plot ROC curve"""
        from sklearn.metrics import roc_curve, auc, roc_auc_score
        
        y_true = self.df['is_attacker'].astype(int)
        y_score = self.df['risk_score'].values
        
        fpr, tpr, thresholds = roc_curve(y_true, y_score)
        roc_auc = auc(fpr, tpr)
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        ax.plot(fpr, tpr, color='darkorange', lw=2.5, 
               label=f'ROC Curve (AUC = {roc_auc:.4f})')
        ax.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
        
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        ax.set_xlabel('False Positive Rate (FPR)', fontsize=12, weight='bold')
        ax.set_ylabel('True Positive Rate (TPR)', fontsize=12, weight='bold')
        ax.set_title(f'ROC Curve - Attackers: {self.attacker_range}', 
                    fontsize=14, weight='bold', pad=20)
        ax.legend(loc="lower right", fontsize=11)
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            print(f"ROC curve saved: {output_path}")
        else:
            plt.show()
        
        plt.close()
    
    def export_report(self, output_dir: Path = None) -> Dict[str, Any]:
        """Export analysis report (JSON format)"""
        if output_dir is None:
            output_dir = self.csv_path.parent
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Build report
        report = {
            'analysis_config': {
                'csv_file': str(self.csv_path),
                'attacker_range': self.attacker_range,
                'total_records': len(self.df),
                'total_attackers': int(sum(self.df['is_attacker'])),
                'total_normal_users': int(sum(~self.df['is_attacker']))
            },
            'confusion_matrix': self.metrics['confusion_matrix'],
            'kpi': {k: float(v) for k, v in self.metrics['kpi'].items()}
        }
        
        # Save JSON report
        report_path = output_dir / f'analysis_report_{self.attacker_range}.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\nJSON report saved: {report_path}")
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='Analyze inference results with confusion matrix, KPI and visualizations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze_inference.py inference_20251225_092222.csv 46-50
  python analyze_inference.py inference_20251225_092222.csv 46-50 -o /path/to/output
        """
    )
    
    parser.add_argument('csv_file', help='Inference result CSV file')
    parser.add_argument('attacker_range', help='Attacker range, format: start-end (e.g., 46-50)')
    parser.add_argument('--output-dir', '-o', default=None, 
                       help='Output directory (default: same as CSV file)')
    parser.add_argument('--no-plots', action='store_true', 
                       help='Only generate report, not plots')
    
    args = parser.parse_args()
    
    # Check if CSV file exists
    if not Path(args.csv_file).exists():
        print(f"Error: CSV file not found: {args.csv_file}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Create analyzer
        analyzer = InferenceAnalyzer(args.csv_file, args.attacker_range)
        
        # Execute analysis
        analyzer.analyze()
        
        # Export report
        output_dir = Path(args.output_dir) if args.output_dir else Path(args.csv_file).parent
        analyzer.export_report(output_dir)
        
        # Generate plots
        if not args.no_plots:
            print("\nGenerating plots...")
            
            confusion_matrix_path = output_dir / f'confusion_matrix_{args.attacker_range}.png'
            risk_distribution_path = output_dir / f'risk_distribution_{args.attacker_range}.png'
            risk_progression_path = output_dir / f'risk_progression_{args.attacker_range}.png'
            roc_curve_path = output_dir / f'roc_curve_{args.attacker_range}.png'
            
            analyzer.plot_confusion_matrix(confusion_matrix_path)
            analyzer.plot_risk_accumulation(risk_distribution_path)
            analyzer.plot_risk_progression(risk_progression_path)
            analyzer.plot_roc_curve(roc_curve_path)
            
            print("\nAll plots completed!")
        
        print(f"\nAnalysis complete! Results saved to: {output_dir}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
