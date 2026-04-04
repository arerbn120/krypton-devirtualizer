using System.Collections.Generic;

namespace Krypton.Core
{
    public sealed class ResourceFormatProfile
    {
        public string HeaderMagic { get; set; }
        public string IntegerEncoding { get; set; } = "encrypted-leb128";
        public int MaxStringCount { get; set; } = 0x4000;
        public int MaxMethodCount { get; set; } = 0x8000;
        public int MaxOperandEntries { get; set; } = 256;
        public List<string> PayloadParsers { get; set; } = new List<string> { "legacy" };
    }

    public sealed class DispatcherStrategyProfile
    {
        public int MinDispatcherHandlersAbsolute { get; set; } = 16;
        public int MinDispatcherHandlersDivisor { get; set; } = 8;
        public int InitialSampleBudget { get; set; } = 48;
        public int FullEvaluationMinCandidates { get; set; } = 4;
        public int FullEvaluationMaxCandidates { get; set; } = 24;
        public double FullEvaluationScale { get; set; } = 2.0;
        public int CandidateLogLimit { get; set; } = 12;
        public bool UseHandlerFallbackInference { get; set; } = true;
    }

    public sealed class OpcodeMappingHeuristicsProfile
    {
        public int SignatureGramMaxOps { get; set; } = 96;
        public double SimilarityDiceThreshold { get; set; } = 0.86;
        public int DominantMinimumFrequency { get; set; } = 6;
        public int DominantTopLimit { get; set; } = 8;
        public int JointSearchCombinationLimit { get; set; } = 4096;
        public int StackPenaltyCapGlobal { get; set; } = 64;
        public int StackPenaltyCapWindow { get; set; } = 32;
        public int NeighborVoteMinimum { get; set; } = 3;
        public double NeighborConfidenceMinimum { get; set; } = 0.72;
        public int BranchVoteMinimum { get; set; } = 8;
        public int BranchMarginMinimum { get; set; } = 2;
        public double BranchConfidenceMinimum { get; set; } = 0.45;
        public int BranchDeltaBucketBoundary { get; set; } = 32;
        public double IndexLikeScoreMinimum { get; set; } = 2.25;
        public int OperandObservationMaxSamples { get; set; } = 96;
        public bool AllowOperandType1PopInference { get; set; }
        public double PopInferenceMinConfidence { get; set; } = 0.72;
        public int PopInferenceMinFrequency { get; set; } = 3;
        public int PopInferenceRequiredPenaltyGain { get; set; } = 8;
    }

    public sealed class PatternPriorityOverrideEntry
    {
        public string PatternType { get; set; }
        public int Priority { get; set; }
    }

    public sealed class SemanticValidationProfile
    {
        public bool Enabled { get; set; } = true;
        public int MinimumVmByteOccurrences { get; set; } = 8;
        public double ViolationRateThreshold { get; set; } = 0.25;
        public double LowConfidenceThreshold { get; set; } = 0.8;
        public bool AllowRemap { get; set; } = true;
        public int MinimumViolationImprovement { get; set; } = 2;
        public bool AllowPruneHandlerPatternMappings { get; set; }
        public int MaxStackDepth { get; set; } = 128;
        public int MaxStatesPerInstruction { get; set; } = 16;
    }

    public sealed class ReplacementPolicyProfile
    {
        public bool SkipModuleMethods { get; set; }
        public bool SkipHighPopRatioMethods { get; set; }
        public double HighPopRatioThreshold { get; set; } = 0.5;
        public int HighPopRatioMinInstructionCount { get; set; } = 512;
    }
}
