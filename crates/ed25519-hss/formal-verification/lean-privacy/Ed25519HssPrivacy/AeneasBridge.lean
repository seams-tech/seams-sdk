import Aeneas
import Ed25519HssBoundary.GeneratedVisibleBoundary
import Ed25519HssPrivacy.Model
import Ed25519HssPrivacy.Views
import Ed25519HssPrivacy.Assumptions

namespace Ed25519HssPrivacy

open Ed25519HssBoundary

def bytes32OfGeneratedArray (bytes : Array UInt8 32#usize) : Bytes32 :=
  fun i => bytes[i]

def nonExportBoundaryOfGeneratedVisibleBoundary
    (boundary : GeneratedVisibleBoundary) : NonExportVisibleBoundary :=
  {
    canonicalSeed := bytes32OfGeneratedArray (generatedVisibleBoundaryCanonicalSeed boundary)
    xClientBase := bytes32OfGeneratedArray (generatedVisibleBoundaryClientBase boundary)
    xServerBase := bytes32OfGeneratedArray (generatedVisibleBoundaryServerBase boundary)
  }

def visibleBoundaryOfGeneratedVisibleBoundary
    (boundary : GeneratedVisibleBoundary) : VisibleBoundary :=
  .nonExport (nonExportBoundaryOfGeneratedVisibleBoundary boundary)

theorem nonExportBoundaryOfGeneratedVisibleBoundary_canonicalSeed
    (boundary : GeneratedVisibleBoundary) :
    (nonExportBoundaryOfGeneratedVisibleBoundary boundary).canonicalSeed =
      bytes32OfGeneratedArray (generatedVisibleBoundaryCanonicalSeed boundary) := by
  rfl

theorem nonExportBoundaryOfGeneratedVisibleBoundary_xClientBase
    (boundary : GeneratedVisibleBoundary) :
    (nonExportBoundaryOfGeneratedVisibleBoundary boundary).xClientBase =
      bytes32OfGeneratedArray (generatedVisibleBoundaryClientBase boundary) := by
  rfl

theorem nonExportBoundaryOfGeneratedVisibleBoundary_xServerBase
    (boundary : GeneratedVisibleBoundary) :
    (nonExportBoundaryOfGeneratedVisibleBoundary boundary).xServerBase =
      bytes32OfGeneratedArray (generatedVisibleBoundaryServerBase boundary) := by
  rfl

theorem generatedVisibleBoundary_matchesPrivacyNonExportBoundary
    (boundary : GeneratedVisibleBoundary) :
    NonExportBoundaryEquivalent
      (nonExportBoundaryOfGeneratedVisibleBoundary boundary)
      {
        canonicalSeed := bytes32OfGeneratedArray (generatedVisibleBoundaryCanonicalSeed boundary)
        xClientBase := bytes32OfGeneratedArray (generatedVisibleBoundaryClientBase boundary)
        xServerBase := bytes32OfGeneratedArray (generatedVisibleBoundaryServerBase boundary)
      } := by
  simp [NonExportBoundaryEquivalent, nonExportBoundaryOfGeneratedVisibleBoundary]

theorem visibleBoundaryOfGeneratedVisibleBoundary_allowedOutputKind
    (boundary : GeneratedVisibleBoundary) :
    (visibleBoundaryOfGeneratedVisibleBoundary boundary).allowedOutputKind =
      .clientOutputOnly := by
  rfl

theorem clientView_ofGeneratedVisibleBoundary_usesMappedBoundary
    (publicParameters : PublicParameters)
    (boundary : GeneratedVisibleBoundary) :
    (clientView publicParameters (visibleBoundaryOfGeneratedVisibleBoundary boundary)).boundary =
      nonExportBoundaryOfGeneratedVisibleBoundary boundary := by
  rfl

theorem serverView_ofGeneratedVisibleBoundary_usesMappedBoundary
    (publicParameters : PublicParameters)
    (boundary : GeneratedVisibleBoundary) :
    (serverView publicParameters (visibleBoundaryOfGeneratedVisibleBoundary boundary)).boundary =
      nonExportBoundaryOfGeneratedVisibleBoundary boundary := by
  rfl

end Ed25519HssPrivacy
