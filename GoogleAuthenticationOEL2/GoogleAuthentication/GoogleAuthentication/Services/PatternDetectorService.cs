using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace GoogleAuthentication.Services
{
    public class PatternDetectorService
    {
        public DetectionResult Analyze(string input)
        {
            var sqlPatterns = new List<string>
            {
                @"\bSELECT\s.*\bFROM\b", @"\bINSERT\s.*\bINTO\b", @"\bDROP\sTABLE\b", @"\b--\b"
            };

            var xssPatterns = new List<string>
            {
                @"<script\b", @"javascript:", @"onerror\s*=", @"alert\s*\("
            };

            var result = new DetectionResult { IsSafe = true, DetectedPatterns = new List<DetectedPattern>() };

            foreach (var pattern in sqlPatterns)
            {
                if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                {
                    result.DetectedPatterns.Add(new DetectedPattern { PatternType = "SQL Injection", Pattern = pattern });
                    result.IsSafe = false;
                }
            }

            foreach (var pattern in xssPatterns)
            {
                if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                {
                    result.DetectedPatterns.Add(new DetectedPattern { PatternType = "XSS", Pattern = pattern });
                    result.IsSafe = false;
                }
            }

            return result;
        }
    }

    public class DetectionResult
    {
        public bool IsSafe { get; set; }
        public List<DetectedPattern> DetectedPatterns { get; set; }
    }

    public class DetectedPattern
    {
        public string PatternType { get; set; }
        public string Pattern { get; set; }
    }
}