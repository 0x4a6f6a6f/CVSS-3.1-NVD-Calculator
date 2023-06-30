using System;

public class CVSSCalculator
{
    public static void Main()
    {
        //Input Vector string

        string cvssVector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N/";

        double baseScore = CalculateBaseScore(cvssVector);
        string accessVector = GetAccessVector(cvssVector);
        string accessComplexity = GetAccessComplexity(cvssVector);
        string vectorString = cvssVector;
        string authentication = GetAuthentication(cvssVector);
        string privilegesRequired = GetPrivilegesRequired(cvssVector);
        string confidentialityImpact = GetConfidentialityImpact(cvssVector);
        string integrityImpact = GetIntegrityImpact(cvssVector);
        string availabilityImpact = GetAvailabilityImpact(cvssVector);
        string severity = GetSeverity(baseScore);
        double exploitabilityScore = CalculateExploitabilityScore(cvssVector);
        double impactScore = CalcImpactScore(cvssVector);
        string userInteractionRequired = GetUserInteractionRequired(cvssVector);

        Console.WriteLine("Base Score: " + baseScore);
        Console.WriteLine("Access Vector: " + accessVector);
        Console.WriteLine("Access Complexity: " + accessComplexity);
        Console.WriteLine("Vector String: " + vectorString);
        Console.WriteLine("Authentication: " + authentication);
        Console.WriteLine("Privileges Required: " + privilegesRequired);
        Console.WriteLine("Confidentiality Impact: " + confidentialityImpact);
        Console.WriteLine("Integrity Impact: " + integrityImpact);
        Console.WriteLine("Availability Impact: " + availabilityImpact);
        Console.WriteLine("Severity: " + severity);
        Console.WriteLine("Exploitability Score: " + exploitabilityScore);
        Console.WriteLine("Impact Score: " + impactScore);
        Console.WriteLine("User Interaction Required: " + userInteractionRequired);
    }


    public static double CalcImpactScore(string cvssVector)
    {
        double impactScore = 0;
        string _scope = GetScopeVector(cvssVector);

        double impactScoreISS = CalculateImpactScoreISS(cvssVector);
        if (_scope == "Changed")
        {
            impactScore = 7.52 * (impactScoreISS - 0.029) - 3.25 * Math.Pow((impactScoreISS - 0.02), 15);
        }
        else if (_scope == "Unchanged")
        {
            impactScore = 6.42 * impactScoreISS;
        }

        return Math.Round(impactScore,1);
    }

   
    static double CalculateBaseScore(string cvssVector)
    {
        double impactScore = CalcImpactScore(cvssVector);
        string _scope = GetScopeVector(cvssVector);
        double exploitScore = CalculateExploitabilityScore(cvssVector);


        double baseScore = 0.0;

        if (impactScore <= 0.0)
        {
            baseScore = 0.0;

        }
        else
        {
            if (_scope == "Changed") 
            {
                baseScore = Math.Round(Math.Min(1.08 * (impactScore + exploitScore), 10), 1);
            }
            else if(_scope == "Unchanged")
            {
                baseScore = Math.Round(Math.Min((impactScore + exploitScore), 10),1);
               
            }

           
        }

        return baseScore;
    }

    static string GetScopeVector(string cvssVector)
    {
        int index = cvssVector.IndexOf("/S:") + 3;
        int endIndex = cvssVector.IndexOf("/", index);
        string value = cvssVector.Substring(index, endIndex - index);
        switch (value.ToUpper())
        {
            case "C":
                return "Changed";
            case "U":
                return "Unchanged";
            default:
                throw new ArgumentException("Invalid access vector value: " + value);
        }
    }


    static string GetAccessVector(string cvssVector)
    {
        int index = cvssVector.IndexOf("AV:") + 3;
        int endIndex = cvssVector.IndexOf("/", index);
        string value = cvssVector.Substring(index, endIndex - index);
        switch (value.ToUpper())
        {
            case "N":
                return "Network";
            case "A":
                return "Adjacent Network";
            case "L":
                return "Local";
            case "P":
                return "Physical";
            default:
                throw new ArgumentException("Invalid access vector value: " + value);
        }
    }

    static string GetAccessComplexity(string cvssVector)
    {
        int index = cvssVector.IndexOf("AC:") + 3;
        int endIndex = cvssVector.IndexOf("/", index);
        string value = cvssVector.Substring(index, endIndex - index);
        switch (value.ToUpper())
        {
            case "H":
                return "High";
            case "L":
                return "Low";
            default:
                throw new ArgumentException("Invalid access complexity value: " + value);
        }
    }

    static string GetAuthentication(string cvssVector)
    {
        if (cvssVector.Contains("Au:"))
        {
            int index = cvssVector.IndexOf("Au:") + 3;
            int endIndex = cvssVector.IndexOf("/", index);
            if (endIndex < 0)
            {
                endIndex = cvssVector.Length;
            }
            string value = cvssVector.Substring(index, endIndex - index);
            switch (value.ToUpper())
            {
                case "N":
                    return "None";
                case "S":
                    return "Single";
                case "M":
                    return "Multiple";
                default:
                    throw new ArgumentException("Invalid authentication value: " + value);
            }
        }

        return "NIL";
    }

    static string GetPrivilegesRequired(string cvssVector)
    {
        int index = cvssVector.IndexOf("PR:") + 3;
        int endIndex = cvssVector.IndexOf("/", index);
        string value = cvssVector.Substring(index, endIndex - index);
        switch (value.ToUpper())
        {
            case "N":
                return "None";
            case "L":
                return "Low";
            case "H":
                return "High";
            default:
                throw new ArgumentException("Invalid privileges required value: " + value);
        }
    }

    static string GetConfidentialityImpact(string cvssVector)
    {
        int index = cvssVector.IndexOf("C:") + 2;
        int endIndex = cvssVector.IndexOf("/", index);
        string value = cvssVector.Substring(index, endIndex - index);
        switch (value.ToUpper())
        {
            case "N":
                return "None";
            case "L":
                return "Low";
            case "H":
                return "High";
            default:
                throw new ArgumentException("Invalid confidentiality impact value: " + value);
        }
    }

    static string GetIntegrityImpact(string cvssVector)
    {
        int index = cvssVector.IndexOf("/I:") + 3;
        int endIndex = cvssVector.IndexOf("/", index);
        string value = cvssVector.Substring(index, endIndex - index);
        switch (value.ToUpper())
        {
            case "N":
                return "None";
            case "L":
                return "Low";
            case "H":
                return "High";
            default:
                throw new ArgumentException("Invalid integrity impact value: " + value);
        }
    }

    static string GetAvailabilityImpact(string cvssVector)
    {
        int index = cvssVector.IndexOf("A:") + 2;
        int endIndex = cvssVector.IndexOf("/", index);
        string value = cvssVector.Substring(index, endIndex - index);
        switch (value.ToUpper())
        {
            case "N":
                return "None";
            case "L":
                return "Low";
            case "H":
                return "High";
            default:
                throw new ArgumentException("Invalid availability impact value: " + value);
        }
    }

    static string GetSeverity(double baseScore)
    {
        if (baseScore >= 9.0)
        {
            return "Critical";
        }
        else if (baseScore >= 7.0)
        {
            return "High";
        }
        else if (baseScore >= 4.0)
        {
            return "Medium";
        }
        else if (baseScore >= 0.1)
        {
            return "Low";
        }
        else
        {
            return "None";
        }
    }

    static double CalculateExploitabilityScore(string cvssVector)
    {
        int index = cvssVector.IndexOf("AV:") + 3;
        int endIndex = cvssVector.IndexOf("/", index);
        string accessVector = cvssVector.Substring(index, endIndex - index);

        index = cvssVector.IndexOf("AC:") + 3;
        endIndex = cvssVector.IndexOf("/", index);
        string accessComplexity = cvssVector.Substring(index, endIndex - index);

        index = cvssVector.IndexOf("PR:") + 3;
        endIndex = cvssVector.IndexOf("/", index);
        string privilegesRequired = cvssVector.Substring(index, endIndex - index);

        index = cvssVector.IndexOf("UI:") + 3;
        endIndex = cvssVector.IndexOf("/", index);
        string userInteractionRequired = cvssVector.Substring(index, endIndex - index);

        double exploitabilityScore = 8.22 * CalculateAttackVectorValue(accessVector) *
            CalculateAttackComplexityValue(accessComplexity) *
            CalculatePrivilegesRequiredValue(privilegesRequired) *
            CalculateUserInteractionRequiredValue(userInteractionRequired);

        return Math.Round(exploitabilityScore,1);
    }

    static double CalculateAttackVectorValue(string accessVector)
    {
        switch (accessVector.ToUpper())
        {
            case "N":
                return 0.85;
            case "A":
                return 0.62;
            case "L":
                return 0.55;
            case "P":
                return 0.2;
            default:
                throw new ArgumentException("Invalid access vector value: " + accessVector);
        }
    }

    static double CalculateAttackComplexityValue(string accessComplexity)
    {
        switch (accessComplexity.ToUpper())
        {
            case "H":
                return 0.44;
            case "L":
                return 0.77;
            default:
                throw new ArgumentException("Invalid access complexity value: " + accessComplexity);
        }
    }

    static double CalculatePrivilegesRequiredValue(string privilegesRequired)
    {
        switch (privilegesRequired.ToUpper())
        {
            case "N":
                return 0.85;
            case "L":
                return 0.62;
            case "H":
                return 0.27;
            default:
                throw new ArgumentException("Invalid privileges required value: " + privilegesRequired);
        }
    }

    static double CalculateUserInteractionRequiredValue(string userInteractionRequired)
    {
        switch (userInteractionRequired.ToUpper())
        {
            case "N":
                return 0.85;
            case "R":
                return 0.62;
            default:
                throw new ArgumentException("Invalid user interaction required value: " + userInteractionRequired);
        }
    }

    static double CalculateImpactScoreISS(string cvssVector)
    {
        int index = cvssVector.IndexOf("/C:") + 3;
        int endIndex = cvssVector.IndexOf("/", index);
        string confidentialityImpact = cvssVector.Substring(index, endIndex - index);

        index = cvssVector.IndexOf("/I:") + 3;
        endIndex = cvssVector.IndexOf("/", index);
        string integrityImpact = cvssVector.Substring(index, endIndex - index);

        index = cvssVector.IndexOf("/A:") + 3;
        endIndex = cvssVector.IndexOf("/", index);
        string availabilityImpact = cvssVector.Substring(index, endIndex - index);

        double confd = CalculateImpactSubScore(confidentialityImpact);
        double integrity = CalculateImpactSubScore(integrityImpact);
        double aval = CalculateImpactSubScore(availabilityImpact);

        //ISS=	1 - [ (1 - Confidentiality) × (1 - Integrity) × (1 - Availability) ]

        double impactScore = 1 - ((1 - confd) * (1 - integrity) * (1 - aval));

        return impactScore;
    }
    //CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"

    static double CalculateImpactSubScore(string impact)
    {
        switch (impact.ToUpper())
        {
            case "N":
                return 0.0;
            case "L":
                return 0.22;
            case "H":
                return 0.56;
            default:
                throw new ArgumentException("Invalid impact value: " + impact);
        }
    }

    static string GetUserInteractionRequired(string cvssVector)
    {
        int index = cvssVector.IndexOf("UI:") + 3;
        int endIndex = cvssVector.IndexOf("/", index);
        string value = cvssVector.Substring(index, endIndex - index);
        switch (value.ToUpper())
        {
            case "N":
                return "None";
            case "R":
                return "Required";
            default:
                throw new ArgumentException("Invalid user interaction required value: " + value);
        }
    }
}
