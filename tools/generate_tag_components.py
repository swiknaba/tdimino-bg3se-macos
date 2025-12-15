#!/usr/bin/env python3
"""
generate_tag_components.py - Generate tag component entries for BG3SE-macOS

Matches tag component definitions from Windows BG3SE headers against
TypeId addresses from the macOS binary to generate component_typeid.c
and component_offsets.h entries.

Usage:
    python3 tools/generate_tag_components.py
"""

import subprocess
import re
import sys
from pathlib import Path

# Binary path
DEFAULT_BINARY = "/Users/tomdimino/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3"

# Tag components from Windows BG3SE DEFINE_TAG_COMPONENT macros
# Format: (namespace::component, short_name)
TAG_COMPONENTS = [
    ("ecl::camera::IsInSelectorModeComponent", "CameraInSelectorMode"),
    ("ecl::camera::SpellTrackingComponent", "CameraSpellTracking"),
    ("ecl::dummy::IsCopyingFullPoseComponent", "DummyIsCopyingFullPose"),
    ("ecl::dummy::LoadedComponent", "DummyLoaded"),
    ("eoc::active_roll::InProgressComponent", "RollInProgress"),
    ("eoc::ambush::AmbushingComponent", "Ambushing"),
    ("eoc::camp::PresenceComponent", "CampPresence"),
    ("eoc::CanTriggerRandomCastsComponent", "CanTriggerRandomCasts"),
    ("eoc::character::CharacterComponent", "IsCharacter"),
    ("eoc::ClientControlComponent", "ClientControl"),
    ("eoc::combat::DelayedFanfareComponent", "CombatDelayedFanfare"),
    ("eoc::combat::IsInCombatComponent", "IsInCombat"),
    ("eoc::exp::CanLevelUpComponent", "CanLevelUp"),
    ("eoc::falling::IsFallingComponent", "IsFalling"),
    ("eoc::ftb::IsFtbPausedComponent", "FTBPaused"),
    ("eoc::ftb::IsInFtbComponent", "IsInFTB"),
    ("eoc::GravityDisabledComponent", "GravityDisabled"),
    ("eoc::heal::BlockComponent", "HealBlock"),
    ("eoc::heal::MaxIncomingComponent", "HealMaxIncoming"),
    ("eoc::heal::MaxOutgoingComponent", "HealMaxOutgoing"),
    ("eoc::improvised_weapon::CanBeWieldedComponent", "CanBeWielded"),
    ("eoc::inventory::CanBeInComponent", "CanBeInInventory"),
    ("eoc::inventory::CannotBePickpocketedComponent", "CannotBePickpocketed"),
    ("eoc::inventory::CannotBeTakenOutComponent", "CannotBeTakenOut"),
    ("eoc::inventory::DropOnDeathBlockedComponent", "DropOnDeathBlocked"),
    ("eoc::inventory::IsLockedComponent", "InventoryLocked"),
    ("eoc::inventory::NewItemsInsideComponent", "NewItemsInside"),
    ("eoc::inventory::NonTradableComponent", "NonTradable"),
    ("eoc::IsInTurnBasedModeComponent", "IsInTurnBasedMode"),
    ("eoc::item_template::CanMoveComponent", "ItemCanMove"),
    ("eoc::item_template::ClimbOnComponent", "ClimbOn"),
    ("eoc::item_template::DestroyedComponent", "ItemTemplateDestroyed"),
    ("eoc::item_template::InteractionDisabledComponent", "InteractionDisabled"),
    ("eoc::item_template::IsStoryItemComponent", "IsStoryItem"),
    ("eoc::item_template::LadderComponent", "Ladder"),
    ("eoc::item_template::WalkOnComponent", "WalkOn"),
    ("eoc::item::DestroyingComponent", "ItemDestroying"),
    ("eoc::item::DoorComponent", "IsDoor"),
    ("eoc::item::ExamineDisabledComponent", "ExamineDisabled"),
    ("eoc::item::HasMovedComponent", "ItemHasMoved"),
    ("eoc::item::HasOpenedComponent", "HasOpened"),
    ("eoc::item::InUseComponent", "ItemInUse"),
    ("eoc::item::IsGoldComponent", "IsGold"),
    ("eoc::item::IsPoisonedComponent", "ItemIsPoisoned"),
    ("eoc::item::ItemComponent", "IsItem"),
    ("eoc::item::NewInInventoryComponent", "NewInInventory"),
    ("eoc::item::ShouldDestroyOnSpellCastComponent", "ShouldDestroyOnSpellCast"),
    ("eoc::multiplayer::HostComponent", "MultiplayerHost"),
    ("eoc::OffStageComponent", "OffStage"),
    ("eoc::ownership::OwnedAsLootComponent", "OwnedAsLoot"),
    ("eoc::party::BlockFollowComponent", "BlockFollow"),
    ("eoc::party::CurrentlyFollowingPartyComponent", "CurrentlyFollowingParty"),
    ("eoc::PickingStateComponent", "PickingState"),
    ("eoc::pickup::PickUpExecutingComponent", "PickUpExecuting"),
    ("eoc::PlayerComponent", "Player"),
    ("eoc::rest::LongRestInScriptPhase", "LongRestInScriptPhase"),
    ("eoc::rest::ShortRestComponent", "ShortRest"),
    ("eoc::SimpleCharacterComponent", "SimpleCharacter"),
    ("eoc::spell_cast::CanBeTargetedComponent", "SpellCastCanBeTargeted"),
    ("eoc::status::IndicateDarknessComponent", "StatusIndicateDarkness"),
    ("eoc::tadpole_tree::FullIllithidComponent", "FullIllithid"),
    ("eoc::tadpole_tree::HalfIllithidComponent", "HalfIllithid"),
    ("eoc::tadpole_tree::TadpoledComponent", "Tadpoled"),
    ("eoc::tag::AvatarComponent", "Avatar"),
    ("eoc::tag::HasExclamationDialogComponent", "HasExclamationDialog"),
    ("eoc::tag::TraderComponent", "Trader"),
    ("eoc::through::CanSeeThroughComponent", "CanSeeThrough"),
    ("eoc::through::CanShootThroughComponent", "CanShootThrough"),
    ("eoc::through::CanWalkThroughComponent", "CanWalkThrough"),
    ("eoc::trade::CanTradeComponent", "CanTrade"),
    ("esv::boost::StatusBoostsProcessedComponent", "ServerStatusBoostsProcessed"),
    ("esv::character_creation::IsCustomComponent", "ServerCCIsCustom"),
    ("esv::combat::CanStartCombatComponent", "ServerCanStartCombat"),
    ("esv::combat::FleeBlockedComponent", "ServerFleeBlocked"),
    ("esv::combat::ImmediateJoinComponent", "ServerImmediateJoin"),
    ("esv::combat::LeaveRequestComponent", "ServerCombatLeaveRequest"),
    ("esv::cover::IsLightBlockerComponent", "ServerIsLightBlocker"),
    ("esv::cover::IsVisionBlockerComponent", "ServerIsVisionBlocker"),
    ("esv::darkness::DarknessActiveComponent", "ServerDarknessActive"),
    ("esv::death::DeathContinueComponent", "ServerDeathContinue"),
    ("esv::escort::HasStragglersComponent", "EscortHasStragglers"),
    ("esv::hotbar::OrderComponent", "ServerHotbarOrder"),
    ("esv::inventory::CharacterHasGeneratedTradeTreasureComponent", "CharacterHasGeneratedTradeTreasure"),
    ("esv::inventory::EntityHasGeneratedTreasureComponent", "HasGeneratedTreasure"),
    ("esv::inventory::IsReplicatedWithComponent", "ServerInventoryIsReplicatedWith"),
    ("esv::inventory::ReadyToBeAddedToInventoryComponent", "ReadyToBeAddedToInventory"),
    ("esv::IsMarkedForDeletionComponent", "IsMarkedForDeletion"),
    ("esv::level::InventoryItemDataPopulatedComponent", "ServerInventoryItemDataPopulated"),
    ("esv::NetComponent", "Net"),
    ("esv::rest::ShortRestConsumeResourcesComponent", "ShortRestConsumeResources"),
    ("esv::ScriptPropertyCanBePickpocketedComponent", "ScriptPropertyCanBePickpocketed"),
    ("esv::ScriptPropertyIsDroppedOnDeathComponent", "ScriptPropertyIsDroppedOnDeath"),
    ("esv::ScriptPropertyIsTradableComponent", "ScriptPropertyIsTradable"),
    ("esv::sight::EventsEnabledComponent", "ServerSightEventsEnabled"),
    ("esv::spell_cast::ClientInitiatedComponent", "ServerSpellClientInitiated"),
    ("esv::status::ActiveComponent", "ServerStatusActive"),
    ("esv::status::AddedFromSaveLoadComponent", "ServerStatusAddedFromSaveLoad"),
    ("esv::status::AuraComponent", "ServerStatusAura"),
    ("esv::summon::IsUnsummoningComponent", "ServerIsUnsummoning"),
    ("esv::trigger::LoadedHandledComponent", "ServerTriggerLoadedHandled"),
    ("esv::trigger::TriggerWorldAutoTriggeredComponent", "ServerTriggerWorldAutoTriggered"),
    ("esv::TurnOrderSkippedComponent", "TurnOrderSkipped"),
    ("esv::VariableManagerComponent", "ServerVariableManager"),
    ("ls::AlwaysUpdateEffectComponent", "AlwaysUpdateEffect"),
    ("ls::AnimationUpdateComponent", "AnimationUpdate"),
    ("ls::game::PauseComponent", "Pause"),
    ("ls::game::PauseExcludedComponent", "PauseExcluded"),
    ("ls::IsGlobalComponent", "IsGlobal"),
    ("ls::IsSeeThroughComponent", "IsSeeThrough"),
    ("ls::level::LevelInstanceUnloadingComponent", "LevelInstanceUnloading"),
    ("ls::LevelIsOwnerComponent", "LevelIsOwner"),
    ("ls::LevelPrepareUnloadBusyComponent", "LevelPrepareUnloadBusy"),
    ("ls::LevelUnloadBusyComponent", "LevelUnloadBusy"),
    ("ls::SavegameComponent", "Savegame"),
    ("ls::VisualLoadedComponent", "VisualLoaded"),
]


def extract_all_typeids(binary_path: str) -> dict:
    """Extract all TypeId addresses from the binary."""
    cmd = f'nm -gU "{binary_path}" 2>/dev/null | c++filt'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error running nm: {result.stderr}", file=sys.stderr)
        return {}

    # Pattern: ADDRESS D ls::TypeId<COMPONENT, ecs::ComponentTypeIdContext>::m_TypeIndex
    pattern = re.compile(
        r'^([0-9a-f]+)\s+D\s+ls::TypeId<([^,]+),\s*ecs::ComponentTypeIdContext>::m_TypeIndex$'
    )

    components = {}
    for line in result.stdout.splitlines():
        if 'guard variable' in line:
            continue
        match = pattern.match(line)
        if match:
            address = int(match.group(1), 16)
            component_name = match.group(2).strip()
            components[component_name] = address

    return components


def match_tag_components(all_typeids: dict) -> tuple:
    """Match tag components against TypeId database."""
    found = []
    not_found = []

    for full_name, short_name in TAG_COMPONENTS:
        # Try exact match first
        if full_name in all_typeids:
            found.append((full_name, short_name, all_typeids[full_name]))
            continue

        # Try variations (some components have slightly different names)
        matched = False
        component_part = full_name.split("::")[-1]  # e.g., "AvatarComponent"

        for typeid_name, addr in all_typeids.items():
            if typeid_name.endswith(component_part):
                # Check namespace compatibility
                if full_name.replace("::", "").lower() in typeid_name.replace("::", "").lower():
                    found.append((full_name, short_name, addr))
                    matched = True
                    break

        if not matched:
            not_found.append((full_name, short_name))

    return found, not_found


def generate_typeid_entries(found: list) -> str:
    """Generate component_typeid.c entries."""
    lines = []
    lines.append("    // =====================================================================")
    lines.append("    // Tag Components (Issue #33) - Zero-field presence components")
    lines.append("    // Generated by tools/generate_tag_components.py")
    lines.append("    // =====================================================================")

    # Group by namespace
    by_ns = {}
    for full_name, short_name, addr in found:
        ns = full_name.split("::")[0]
        if ns not in by_ns:
            by_ns[ns] = []
        by_ns[ns].append((full_name, short_name, addr))

    for ns in sorted(by_ns.keys()):
        lines.append(f"\n    // {ns}:: tag components")
        for full_name, short_name, addr in sorted(by_ns[ns]):
            lines.append(f'    {{ "{full_name}", 0x{addr:x}, 0, false }},')

    return "\n".join(lines)


def generate_layout_entries(found: list) -> str:
    """Generate component_offsets.h entries."""
    lines = []
    lines.append("// ============================================================================")
    lines.append("// Tag Components (Issue #33) - Zero-field presence components")
    lines.append("// Generated by tools/generate_tag_components.py")
    lines.append("// Tag components have no fields - their presence on an entity is the data")
    lines.append("// ============================================================================")

    for full_name, short_name, addr in sorted(found, key=lambda x: x[0]):
        # Create a safe C identifier
        safe_name = short_name.replace(" ", "")
        lines.append(f"""
// {short_name} ({full_name})
static const ComponentLayoutDef g_{safe_name}Component_Layout = {{
    .componentName = "{full_name}",
    .shortName = "{short_name}",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
}};""")

    return "\n".join(lines)


def generate_registry_entries(found: list) -> str:
    """Generate g_AllComponentLayouts entries."""
    lines = []
    lines.append("    // Tag components (Issue #33)")
    for full_name, short_name, addr in sorted(found, key=lambda x: x[1]):
        safe_name = short_name.replace(" ", "")
        lines.append(f"    &g_{safe_name}Component_Layout,")
    return "\n".join(lines)


def main():
    binary_path = DEFAULT_BINARY

    # Check for alternate binary location
    alt_binary = "/Applications/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3"
    if Path(alt_binary).exists():
        binary_path = alt_binary

    print(f"Extracting TypeIds from: {binary_path}", file=sys.stderr)
    all_typeids = extract_all_typeids(binary_path)
    print(f"Found {len(all_typeids)} total TypeId entries", file=sys.stderr)

    found, not_found = match_tag_components(all_typeids)

    print(f"\n=== Tag Component Match Results ===", file=sys.stderr)
    print(f"Found: {len(found)}/115 tag components", file=sys.stderr)
    print(f"Not found: {len(not_found)}/115 tag components", file=sys.stderr)

    if not_found:
        print(f"\nNot found components:", file=sys.stderr)
        for full_name, short_name in not_found[:10]:
            print(f"  - {full_name} ({short_name})", file=sys.stderr)
        if len(not_found) > 10:
            print(f"  ... and {len(not_found) - 10} more", file=sys.stderr)

    # Generate output
    print("\n" + "=" * 70)
    print("=== component_typeid.c entries ===")
    print("=" * 70)
    print(generate_typeid_entries(found))

    print("\n" + "=" * 70)
    print("=== component_offsets.h layout definitions ===")
    print("=" * 70)
    print(generate_layout_entries(found))

    print("\n" + "=" * 70)
    print("=== g_AllComponentLayouts registry entries ===")
    print("=" * 70)
    print(generate_registry_entries(found))


if __name__ == "__main__":
    main()
