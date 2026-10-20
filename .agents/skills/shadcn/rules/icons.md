# Icons

**Always import icons from the design system package** (`@tamtt-labs/design-system`), which exports from `lucide-animated`. The `iconLibrary` field in `components.json` is set to `"lucide"` for shadcn CLI compatibility. All icons are animated by default via Framer Motion.

## Icon Library Architecture

The design system uses a **hybrid icon system** combining animated and static icons:

- **Animated icons** (from `lucide-animated`): Animate on hover via Framer Motion
  - ChevronDownIcon, ChevronRightIcon, HomeIcon, MenuIcon, RouteIcon, SparklesIcon, WavesIcon, XIcon, ZapIcon

- **Static icons** (from `lucide-react`): Fallback for icons not available in lucide-animated
  - NetworkIcon, ServerIcon, ShieldIcon, SquareFunctionIcon, StickyNoteIcon

Both types use the same import: `import { IconName } from "@tamtt-labs/design-system"` and follow the "Icon" suffix convention.

---

## Icons in Button use data-icon attribute

Add `data-icon="inline-start"` (prefix) or `data-icon="inline-end"` (suffix) to the icon. No sizing classes on the icon.

**Incorrect:**

```tsx
<Button>
  <SearchIcon className="mr-2 size-4" />
  Search
</Button>
```

**Correct:**

```tsx
<Button>
  <SearchIcon data-icon="inline-start"/>
  Search
</Button>

<Button>
  Next
  <ArrowRightIcon data-icon="inline-end"/>
</Button>
```

---

## No sizing classes on icons inside components

Components handle icon sizing via CSS. Don't add `size-4`, `w-4 h-4`, or other sizing classes to icons inside `Button`, `DropdownMenuItem`, `Alert`, `Sidebar*`, or other shadcn components. Unless the user explicitly asks for custom icon sizes.

**Incorrect:**

```tsx
<Button>
  <SearchIcon className="size-4" data-icon="inline-start" />
  Search
</Button>

<DropdownMenuItem>
  <SettingsIcon className="mr-2 size-4" />
  Settings
</DropdownMenuItem>
```

**Correct:**

```tsx
<Button>
  <SearchIcon data-icon="inline-start" />
  Search
</Button>

<DropdownMenuItem>
  <SettingsIcon />
  Settings
</DropdownMenuItem>
```

---

## Pass icons as component objects, not string keys

Use `icon={CheckIcon}`, not a string key to a lookup map.

**Incorrect:**

```tsx
const iconMap = {
  check: CheckIcon,
  alert: AlertIcon,
};

function StatusBadge({ icon }: { icon: string }) {
  const Icon = iconMap[icon];
  return <Icon />;
}

<StatusBadge icon="check" />;
```

**Correct:**

```tsx
// Import from the project's configured iconLibrary (e.g. lucide-react, @tabler/icons-react).
import { CheckIcon } from "lucide-react";

function StatusBadge({ icon: Icon }: { icon: React.ComponentType }) {
  return <Icon />;
}

<StatusBadge icon={CheckIcon} />;
```
