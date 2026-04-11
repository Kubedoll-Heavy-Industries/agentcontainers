package orgpolicy

import (
	"errors"
	"fmt"
)

// IsAtLeastAsRestrictive returns nil if candidate is at least as restrictive
// as base, or a descriptive error listing every field where candidate weakens
// the policy. Passing nil for either argument is treated as the empty (most
// permissive) policy; a nil base means anything goes.
//
// A candidate "weakens" a field when it relaxes a constraint that base set:
//   - RequireSignatures: base true → candidate false
//   - MinSLSALevel:      candidate < base
//   - RequireSBOM:       base true → candidate false
//   - MaxDriftThreshold: base non-zero, candidate zero or higher than base
//   - BannedPackages:    any package banned by base is missing from candidate
//   - DeniedCapabilities: any capability denied by base is missing from candidate
//   - AllowedCapabilities: base non-empty and candidate empty (open-by-default),
//     or candidate permits a capability base did not
//   - AllowedMCPImages: base non-empty and candidate empty (open-by-default),
//     or candidate permits an image pattern base did not
func IsAtLeastAsRestrictive(base, candidate *OrgPolicy) error {
	if base == nil {
		return nil
	}
	if candidate == nil {
		candidate = DefaultPolicy()
	}

	var errs []error

	if base.RequireSignatures && !candidate.RequireSignatures {
		errs = append(errs, fmt.Errorf("requireSignatures weakened: base requires signatures, candidate does not"))
	}

	if candidate.MinSLSALevel < base.MinSLSALevel {
		errs = append(errs, fmt.Errorf("minSLSALevel weakened: base requires %d, candidate allows %d", base.MinSLSALevel, candidate.MinSLSALevel))
	}

	if base.RequireSBOM && !candidate.RequireSBOM {
		errs = append(errs, fmt.Errorf("requireSBOM weakened: base requires SBOM, candidate does not"))
	}

	if base.MaxDriftThreshold > 0 {
		if candidate.MaxDriftThreshold == 0 {
			errs = append(errs, fmt.Errorf("maxDriftThreshold weakened: base sets %.4g, candidate removes the limit", base.MaxDriftThreshold))
		} else if candidate.MaxDriftThreshold > base.MaxDriftThreshold {
			errs = append(errs, fmt.Errorf("maxDriftThreshold weakened: base sets %.4g, candidate raises it to %.4g", base.MaxDriftThreshold, candidate.MaxDriftThreshold))
		}
	}

	if missingBanned := missingFrom(base.BannedPackages, candidate.BannedPackages); len(missingBanned) > 0 {
		for _, pkg := range missingBanned {
			errs = append(errs, fmt.Errorf("bannedPackages weakened: %q is banned by base but not by candidate", pkg))
		}
	}

	if missingDenied := missingFrom(base.DeniedCapabilities, candidate.DeniedCapabilities); len(missingDenied) > 0 {
		for _, cap := range missingDenied {
			errs = append(errs, fmt.Errorf("deniedCapabilities weakened: %q is denied by base but not by candidate", cap))
		}
	}

	if errs2 := compareTrustedRegistries(base.TrustedRegistries, candidate.TrustedRegistries); len(errs2) > 0 {
		errs = append(errs, errs2...)
	}

	if errs2 := compareAllowedCapabilities(base.AllowedCapabilities, candidate.AllowedCapabilities); len(errs2) > 0 {
		errs = append(errs, errs2...)
	}

	if errs2 := compareAllowedMCPImages(base.AllowedMCPImages, candidate.AllowedMCPImages); len(errs2) > 0 {
		errs = append(errs, errs2...)
	}

	return errors.Join(errs...)
}

// compareTrustedRegistries returns errors when candidate's registry allowlist
// is less restrictive than base's.
//
// Rules:
//   - base empty (allow-all): no restriction to weaken, always ok
//   - base non-empty, candidate empty: candidate allows all registries — weakens
//   - base non-empty, candidate non-empty: candidate must not add registries
//     that base did not allow (i.e. candidate ⊆ base, by exact pattern match)
func compareTrustedRegistries(base, candidate []string) []error {
	if len(base) == 0 {
		return nil
	}

	if len(candidate) == 0 {
		return []error{fmt.Errorf("trustedRegistries weakened: base restricts to %v but candidate allows all registries", base)}
	}

	baseSet := toSet(base)
	var errs []error
	for _, reg := range candidate {
		if !baseSet[reg] {
			errs = append(errs, fmt.Errorf("trustedRegistries weakened: candidate permits %q which base did not allow", reg))
		}
	}
	return errs
}

// compareAllowedCapabilities returns errors when candidate's capability allowlist
// is less restrictive than base's.
//
// Rules:
//   - base empty (allow-all): no restriction to weaken, always ok
//   - base non-empty, candidate empty: candidate becomes allow-all — weakens
//   - base non-empty, candidate non-empty: candidate must not add capabilities
//     that base did not allow (i.e. candidate ⊆ base)
func compareAllowedCapabilities(base, candidate []string) []error {
	if len(base) == 0 {
		return nil
	}

	if len(candidate) == 0 {
		return []error{fmt.Errorf("allowedCapabilities weakened: base restricts to %v but candidate allows all capabilities", base)}
	}

	baseSet := toSet(base)
	var errs []error
	for _, c := range candidate {
		if !baseSet[c] {
			errs = append(errs, fmt.Errorf("allowedCapabilities weakened: candidate permits %q which base did not allow", c))
		}
	}
	return errs
}

// compareAllowedMCPImages returns errors when candidate's MCP image allowlist
// is less restrictive than base's. The rules mirror compareAllowedCapabilities.
func compareAllowedMCPImages(base, candidate []string) []error {
	if len(base) == 0 {
		return nil
	}

	if len(candidate) == 0 {
		return []error{fmt.Errorf("allowedMCPImages weakened: base restricts to %v but candidate allows all images", base)}
	}

	baseSet := toSet(base)
	var errs []error
	for _, img := range candidate {
		if !baseSet[img] {
			errs = append(errs, fmt.Errorf("allowedMCPImages weakened: candidate permits %q which base did not allow", img))
		}
	}
	return errs
}

// missingFrom returns entries that are in required but absent from actual.
func missingFrom(required, actual []string) []string {
	if len(required) == 0 {
		return nil
	}
	actualSet := toSet(actual)
	var missing []string
	for _, v := range required {
		if !actualSet[v] {
			missing = append(missing, v)
		}
	}
	return missing
}

// toSet converts a slice to a membership map.
func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, v := range items {
		s[v] = true
	}
	return s
}
