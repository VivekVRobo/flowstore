package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"flowstore/internal/catalog"
	"flowstore/internal/crypto"
	"flowstore/internal/erasure"
	"flowstore/internal/network"
	"flowstore/internal/object"
	"flowstore/internal/snapshot"
	"flowstore/internal/storage"
)

type stringSlice []string

const configDirEnv = "FLOWSTORE_CONFIG_DIR"

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(val string) error {
	*s = append(*s, val)
	return nil
}

func collectPeers(peerFlags []string, peersFlag string) []string {
	var peers []string
	peers = append(peers, peerFlags...)
	if peersFlag != "" {
		for _, p := range strings.Split(peersFlag, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				peers = append(peers, p)
			}
		}
	}
	return peers
}

func normalizeArgs(args []string, boolFlags map[string]bool) []string {
	var flags []string
	var positionals []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			name := strings.TrimLeft(strings.Split(arg, "=")[0], "-")
			if !strings.Contains(arg, "=") && !boolFlags[name] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
		} else {
			positionals = append(positionals, arg)
		}
	}
	return append(flags, positionals...)
}

func flowstoreConfigDir() (string, error) {
	if configDir := os.Getenv(configDirEnv); configDir != "" {
		absConfigDir, err := filepath.Abs(configDir)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", configDirEnv, err)
		}
		return absConfigDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to locate user home directory: %w", err)
	}
	return filepath.Join(home, ".flowstore"), nil
}

func loadKeyring() (*crypto.Keyring, string, error) {
	configDir, err := flowstoreConfigDir()
	if err != nil {
		return nil, "", err
	}
	secretPath := filepath.Join(configDir, "recovery.secret")
	data, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, "", fmt.Errorf("no active identity found. Run 'flow init' first: %w", err)
	}

	code := strings.TrimSpace(string(data))
	secret, err := crypto.ParseRecoveryCode(code)
	if err != nil {
		return nil, "", fmt.Errorf("corrupt recovery secret in %s: %w", secretPath, err)
	}

	kr, err := crypto.DeriveKeyring(secret)
	if err != nil {
		return nil, "", fmt.Errorf("failed deriving keyring: %w", err)
	}

	return kr, code, nil
}

func loadOrCreateCatalog(ownerID string, catalogKey []byte) (*catalog.Catalog, error) {
	configDir, err := flowstoreConfigDir()
	if err != nil {
		return nil, err
	}
	catPath := filepath.Join(configDir, "catalog.json")
	data, err := os.ReadFile(catPath)
	if errors.Is(err, os.ErrNotExist) {
		return catalog.NewCatalog(ownerID), nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed reading local catalog %s: %w", catPath, err)
	}
	cat, legacyPlaintext, err := catalog.UnmarshalCatalog(data, catalogKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load local catalog %s: %w", catPath, err)
	}
	if cat.OwnerID != ownerID {
		return nil, fmt.Errorf("local catalog owner %s does not match active identity %s", cat.OwnerID, ownerID)
	}
	if legacyPlaintext {
		if err := saveCatalog(cat, catalogKey); err != nil {
			return nil, fmt.Errorf("failed migrating legacy plaintext catalog to encrypted storage: %w", err)
		}
	}
	return cat, nil
}

func saveCatalog(cat *catalog.Catalog, catalogKey []byte) error {
	configDir, err := flowstoreConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create local FlowStore directory: %w", err)
	}
	catPath := filepath.Join(configDir, "catalog.json")
	data, err := catalog.MarshalEncryptedCatalog(cat, catalogKey)
	if err != nil {
		return err
	}
	return writeFileAtomic(catPath, data, 0600)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file beside %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set permissions on temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed writing temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed syncing temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed closing temporary file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to atomically replace %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("manifest was renamed but its directory could not be opened for sync: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("manifest was renamed but its directory sync failed: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("manifest was renamed but its directory close failed: %w", closeErr)
		}
	}
	return nil
}

type manifestDescriptor struct {
	Inline *object.Manifest
	Paged  *object.PagedManifest
}

func loadManifestFile(path string, catalogKey []byte) (*manifestDescriptor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}
	if object.IsPagedManifestEnvelope(data) {
		manifest, err := object.UnmarshalEncryptedPagedManifest(data, catalogKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse paged manifest file: %w", err)
		}
		return &manifestDescriptor{Paged: manifest}, nil
	}
	manifest, legacyPlaintext, err := object.UnmarshalManifest(data, catalogKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest file: %w", err)
	}
	if legacyPlaintext {
		fmt.Fprintf(os.Stderr, "Warning: %s is a legacy plaintext manifest containing per-chunk keys; keep it private. New ingests write encrypted manifests.\n", path)
	}
	return &manifestDescriptor{Inline: manifest}, nil
}

func (m *manifestDescriptor) objectID() string {
	if m == nil {
		return ""
	}
	if m.Inline != nil {
		return m.Inline.ObjectID
	}
	if m.Paged != nil {
		return m.Paged.Header.ObjectID
	}
	return ""
}

func (m *manifestDescriptor) logicalPath() string {
	if m.Inline != nil {
		return m.Inline.Path
	}
	if m.Paged != nil {
		return m.Paged.Header.Path
	}
	return ""
}

func (m *manifestDescriptor) chunkSize() uint32 {
	if m.Inline != nil {
		return m.Inline.ChunkSize
	}
	if m.Paged != nil {
		return m.Paged.Header.ChunkSize
	}
	return 0
}

func (m *manifestDescriptor) addToCatalog(cat *catalog.Catalog) error {
	if m.Inline != nil {
		cat.AddFile(m.Inline)
		return nil
	}
	if m.Paged != nil {
		return cat.AddPagedFile(m.Paged)
	}
	return errors.New("manifest descriptor has neither inline nor paged metadata")
}

func (m *manifestDescriptor) reconstruct(w io.Writer, keyring *crypto.Keyring, getter object.ShardGetter) error {
	if m.Inline != nil {
		pipeline, err := object.NewPipeline(keyring, m.Inline.ChunkSize, 0)
		if err != nil {
			return err
		}
		return pipeline.Reconstruct(w, m.Inline, getter)
	}
	if m.Paged != nil {
		pipeline, err := object.NewPipeline(keyring, m.Paged.Header.ChunkSize, 0)
		if err != nil {
			return err
		}
		return pipeline.ReconstructPagedManifest(w, m.Paged, getter)
	}
	return errors.New("manifest descriptor has neither inline nor paged metadata")
}

// visitStoredChunks visits both the data object's chunks and, for a paged
// descriptor, the chunks holding its encrypted metadata pages.
func (m *manifestDescriptor) visitStoredChunks(keyring *crypto.Keyring, getter object.ShardGetter, visit func(object.ChunkRef) error) error {
	if m.Inline != nil {
		for _, chunk := range m.Inline.Chunks {
			if err := visit(chunk); err != nil {
				return err
			}
		}
		return nil
	}
	if m.Paged == nil {
		return errors.New("manifest descriptor has neither inline nor paged metadata")
	}
	pipeline, err := object.NewPipeline(keyring, m.Paged.Header.ChunkSize, 0)
	if err != nil {
		return err
	}
	if err := pipeline.VisitPagedManifestChunks(m.Paged, getter, visit); err != nil {
		return err
	}
	// Process metadata-page shard refs after their contents have been consumed.
	// This ordering lets flow delete remove the page objects without making later
	// pages unreadable during traversal.
	for pageIndex, pageManifest := range m.Paged.PageManifests {
		if pageManifest == nil {
			return fmt.Errorf("paged manifest has no storage manifest for page %d", pageIndex)
		}
		for _, chunk := range pageManifest.Chunks {
			if err := visit(chunk); err != nil {
				return err
			}
		}
	}
	return nil
}

func reconstructCatalogEntry(w io.Writer, entry catalog.FileEntry, keyring *crypto.Keyring, getter object.ShardGetter) error {
	if entry.Manifest != nil {
		pipeline, err := object.NewPipeline(keyring, entry.Manifest.ChunkSize, 0)
		if err != nil {
			return err
		}
		return pipeline.Reconstruct(w, entry.Manifest, getter)
	}
	if entry.PagedManifest != nil {
		pipeline, err := object.NewPipeline(keyring, entry.PagedManifest.Header.ChunkSize, 0)
		if err != nil {
			return err
		}
		return pipeline.ReconstructPagedManifest(w, entry.PagedManifest, getter)
	}
	return fmt.Errorf("catalog entry %s has no inline or paged manifest", entry.Path)
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h" {
		printUsage()
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "init":
		cmdInit()
	case "keys":
		cmdKeys()
	case "ping":
		cmdPing(os.Args[2:])
	case "ingest":
		if err := cmdIngest(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "audit":
		cmdAudit(os.Args[2:])
	case "recover":
		if err := cmdRecover(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "restore":
		cmdRestore(os.Args[2:])
	case "delete":
		if err := cmdDelete(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "repair-status":
		cmdRepairStatus(os.Args[2:])
	case "snapshot":
		if err := cmdSnapshot(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func cmdSnapshot(args []string) error {
	if len(args) == 0 || args[0] != "capture" {
		return errors.New("usage: flow snapshot capture <stopped-disk-image> -output <snapshot.qcow2> -peer <bootstrap-address>...")
	}
	fs := flag.NewFlagSet("snapshot capture", flag.ContinueOnError)
	qemuImg := fs.String("qemu-img", "qemu-img", "Path to qemu-img on the Linux runner")
	outputPath := fs.String("output", "", "Standalone qcow2 snapshot output path")
	chunkSize := fs.Uint("chunk-size", 64*1024*1024, "FlowStore chunk size in bytes")
	var peerFlags stringSlice
	fs.Var(&peerFlags, "peer", "FlowStore bootstrap peer multiaddress (can be repeated)")
	peersFlag := fs.String("peers", "", "Comma-separated FlowStore bootstrap multiaddresses")
	if err := fs.Parse(normalizeArgs(args[1:], nil)); err != nil {
		return err
	}
	if fs.NArg() != 1 || *outputPath == "" {
		return errors.New("usage: flow snapshot capture <stopped-disk-image> -output <snapshot.qcow2> -peer <bootstrap-address>...")
	}
	peers := collectPeers(peerFlags, *peersFlag)
	if len(peers) == 0 {
		return errors.New("snapshot publication needs at least one bootstrap peer; recovery from a fresh runner requires DHT discovery")
	}
	if *chunkSize == 0 || uint64(*chunkSize) > uint64(^uint32(0)) {
		return fmt.Errorf("invalid chunk size %d: FlowStore supports 1..%d bytes", *chunkSize, ^uint32(0))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	descriptor, err := snapshot.Capture(ctx, *qemuImg, fs.Arg(0), *outputPath)
	if err != nil {
		return err
	}
	metaPath := *outputPath + ".flowmeta.json"
	fmt.Printf("Captured %d-byte qcow2 image with %d changed extents.\n", descriptor.ImageSize, len(descriptor.ChangedBlocks))

	// Ingest both objects without publishing an intermediate catalog. The final
	// catalog update is the snapshot commit point and happens only after both
	// encrypted object manifests and all referenced shards have been verified.
	imageManifestPath := *outputPath + ".flowmanifest.enc"
	if err := cmdIngest(snapshotIngestArgs(peers, uint32(*chunkSize), *outputPath)); err != nil {
		return fmt.Errorf("snapshot disk upload failed; snapshot catalog was not committed: %w", err)
	}
	kr, _, err := loadKeyring()
	if err != nil {
		return err
	}
	imageManifest, err := loadManifestFile(imageManifestPath, kr.CatalogKey[:])
	if err != nil {
		return fmt.Errorf("read committed disk manifest: %w", err)
	}
	descriptor.FlowObjectID = imageManifest.objectID()
	metaBytes, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize snapshot descriptor: %w", err)
	}
	if err := writeFileAtomic(metaPath, metaBytes, 0600); err != nil {
		return fmt.Errorf("write local snapshot descriptor: %w", err)
	}
	metaManifestPath := metaPath + ".flowmanifest.enc"
	if err := cmdIngest(snapshotIngestArgs(peers, uint32(*chunkSize), metaPath)); err != nil {
		return fmt.Errorf("snapshot descriptor upload failed; snapshot catalog was not committed: %w", err)
	}
	if err := publishSnapshotCatalog(ctx, peers, []string{imageManifestPath, metaManifestPath}, kr); err != nil {
		return fmt.Errorf("snapshot objects are stored, but publishing the committed snapshot catalog failed: %w", err)
	}
	fmt.Printf("Snapshot committed to FlowStore. Disk object ID: %s\n", imageManifest.objectID())
	fmt.Printf("Snapshot descriptor: %s\n", metaPath)
	return nil
}

func snapshotIngestArgs(peers []string, chunkSize uint32, path string) []string {
	args := []string{"-catalog=false", "-chunk-size", strconv.FormatUint(uint64(chunkSize), 10)}
	for _, addr := range peers {
		args = append(args, "-peer", addr)
	}
	return append(args, path)
}

func publishSnapshotCatalog(ctx context.Context, peers, manifestPaths []string, kr *crypto.Keyring) error {
	cs, err := network.NewDiscoveryClientSession(ctx, peers)
	if err != nil {
		return fmt.Errorf("connect to storage swarm: %w", err)
	}
	defer cs.Close()
	if len(cs.Peers) < erasure.DefaultTotalShards {
		return fmt.Errorf("snapshot catalog needs %d distinct peers; connected to %d", erasure.DefaultTotalShards, len(cs.Peers))
	}
	id := crypto.NewIdentityFromPrivateKey(kr.IdentityPriv)
	cat, err := loadOrCreateCatalog(id.NodeID(), kr.CatalogKey[:])
	if err != nil {
		return err
	}
	for _, path := range manifestPaths {
		manifest, err := loadManifestFile(path, kr.CatalogKey[:])
		if err != nil {
			return err
		}
		if err := manifest.addToCatalog(cat); err != nil {
			return fmt.Errorf("add %s to catalog: %w", manifest.logicalPath(), err)
		}
	}
	if err := catalog.DistributeCatalog(ctx, cs.Host, cs.DHT, cat, kr, cs.PeerIDs(), 0); err != nil {
		return err
	}
	return saveCatalog(cat, kr.CatalogKey[:])
}

func printUsage() {
	fmt.Println(`FlowStore CLI — Swarm Information System (v0.5)

Usage:
  flow init                                    Generate a new 256-bit master recovery secret
  flow keys                                    Display keys derived from local recovery secret
  flow ping <peer_multiaddr>                   Measure round-trip time and status of a remote peer
  flow ingest <file> [-peer <addr>]...         Stream, encrypt, and distribute file with paged metadata
  flow audit <manifest> [-peer <addr>]...      Challenge swarm peers with zero-knowledge possession proofs
  flow recover <manifest> <out> [-peer <bootstrap-addr>] Reconstruct via DHT-discovered swarm shards
  flow restore <out-dir> -secret-file <path>   Rebuild catalog and restore files using a protected secret file
  flow delete <manifest> [-peer <addr>]...     Explicitly reclaim leased shards for one object
  flow repair-status <peer> [-reannounce]      Query peer storage health and DHT re-announcement
  flow snapshot capture <disk> -output <file>  Capture and commit a stopped Linux VM disk through FlowStore

Options:
  -peer <multiaddr>     Peer multiaddress (can be repeated: -peer ... -peer ...)
  -peers <m1,m2,...>    Comma-separated list of peer multiaddresses
  -chunk-size <bytes>   Chunk size in bytes (default: 64 MiB)
  -page-size <chunks>   Chunks per encrypted manifest page (default: 256, max: 4096)
  -manifest-out <path>  Write the encrypted local recovery descriptor to this path
  -catalog              Publish updated encrypted catalog to swarm peers (default: true)
  -qemu-img             qemu-img executable path for Linux snapshot capture (default: qemu-img)

New ingests write encrypted <file>.flowmanifest.enc files. Legacy plaintext manifests remain readable with a warning.`)
}

func cmdInit() {
	secret, err := crypto.GenerateMasterSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating master secret: %v\n", err)
		os.Exit(1)
	}

	code := crypto.FormatRecoveryCode(secret)
	kr, err := crypto.DeriveKeyring(secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving keyring: %v\n", err)
		os.Exit(1)
	}

	id := crypto.NewIdentityFromPrivateKey(kr.IdentityPriv)

	configDir, err := flowstoreConfigDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to locate FlowStore configuration directory: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create FlowStore configuration directory: %v\n", err)
		os.Exit(1)
	}
	secretPath := filepath.Join(configDir, "recovery.secret")
	if err := os.WriteFile(secretPath, []byte(code), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save recovery secret to %s: %v\n", secretPath, err)
	}

	fmt.Println("=================================================================")
	fmt.Println("             FLOWSTORE INITIALIZATION COMPLETE                  ")
	fmt.Println("=================================================================")
	fmt.Printf("Node Identity (Ed25519 PubKey): %s\n", id.NodeID())
	fmt.Println("\nYOUR MASTER RECOVERY SECRET (Store this offline!):")
	fmt.Printf("  >>> %s <<<\n", code)
	fmt.Printf("\nSaved active secret to: %s\n", secretPath)
}

func cmdKeys() {
	kr, code, err := loadKeyring()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	id := crypto.NewIdentityFromPrivateKey(kr.IdentityPriv)
	fmt.Println("FlowStore Identity:")
	fmt.Printf("  Node ID:     %s\n", id.NodeID())
	fmt.Printf("  Recovery:    %s\n", code)
	fmt.Println("  Catalog Key: [Derived - 256-bit AEAD]")
	fmt.Println("  Routing Key: [Derived - 256-bit HMAC-BLAKE3]")
}

func cmdPing(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: flow ping <peer_multiaddr>")
		os.Exit(1)
	}
	addr := args[0]
	fmt.Printf("Pinging peer at %s...\n", addr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rtt, peerID, err := network.PingPeer(ctx, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ping FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=================================================================")
	fmt.Println("                     PEER PING SUCCESSFUL                        ")
	fmt.Println("=================================================================")
	fmt.Printf("Target Multiaddr:  %s\n", addr)
	fmt.Printf("Remote Peer ID:    %s\n", peerID)
	fmt.Printf("Round-Trip Time:   %v\n", rtt)
	fmt.Println("Status:            ONLINE & RESPONSIVE")
}

func cmdIngest(args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	chunkSizeFlag := fs.Uint("chunk-size", 64*1024*1024, "Chunk size in bytes (default 64 MiB)")
	pageSizeFlag := fs.Uint("page-size", uint(object.DefaultManifestPageSize), "Chunk references per encrypted manifest page (default 256)")
	manifestOut := fs.String("manifest-out", "", "Optional path for the encrypted local recovery descriptor (default <input>.flowmanifest.enc)")
	var peerFlags stringSlice
	fs.Var(&peerFlags, "peer", "Swarm peer multiaddress (can be repeated)")
	peersFlag := fs.String("peers", "", "Comma-separated list of peer multiaddresses")
	publishCatalog := fs.Bool("catalog", true, "Publish updated encrypted catalog to swarm peers")
	fs.Parse(normalizeArgs(args, map[string]bool{"catalog": true}))

	if fs.NArg() < 1 {
		return fmt.Errorf("Usage: flow ingest <file> [-peer <addr>]... [-peers <m1,m2>] [-chunk-size <bytes>]")
	}
	if uint64(*pageSizeFlag) > uint64(^uint32(0)) {
		return fmt.Errorf("invalid page size %d: maximum is %d chunks", *pageSizeFlag, ^uint32(0))
	}
	if *pageSizeFlag > uint(object.MaxManifestPageSize) {
		return fmt.Errorf("invalid page size %d: maximum is %d chunks", *pageSizeFlag, object.MaxManifestPageSize)
	}
	if *pageSizeFlag == 0 {
		*pageSizeFlag = uint(object.DefaultManifestPageSize)
	}

	filePath := fs.Arg(0)
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer f.Close()

	kr, _, err := loadKeyring()
	if err != nil {
		return err
	}
	id := crypto.NewIdentityFromPrivateKey(kr.IdentityPriv)

	pipeline, err := object.NewPipeline(kr, uint32(*chunkSizeFlag), 0)
	if err != nil {
		return fmt.Errorf("pipeline error: %w", err)
	}

	peers := collectPeers(peerFlags, *peersFlag)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var cs *network.ClientSession
	var localStore *storage.FileShardStore
	if len(peers) > 0 {
		fmt.Printf("Connecting to %d swarm peer(s)...\n", len(peers))
		cs, err = network.NewDiscoveryClientSession(ctx, peers)
		if err != nil {
			return fmt.Errorf("network error: %w", err)
		}
		defer cs.Close()
		if len(cs.Peers) < erasure.DefaultTotalShards {
			return fmt.Errorf("distributed ingest requires %d distinct storage peers per chunk; connected to %d", erasure.DefaultTotalShards, len(cs.Peers))
		}
		fmt.Printf("Connected to %d peer(s); shards will be streamed as each chunk is encoded.\n", len(cs.Peers))
	} else {
		localStore, err = storage.NewFileShardStore("./flownode-data/shards")
		if err != nil {
			return fmt.Errorf("failed to open local shard store: %w", err)
		}
		defer localStore.Close()
	}

	fmt.Printf("Ingesting %s (chunk size: %d bytes)...\n", filePath, *chunkSizeFlag)
	storedChunks := 0
	storedShards := 0
	manifestPath := *manifestOut
	if manifestPath == "" {
		manifestPath = filePath + ".flowmanifest.enc"
	}
	storeChunk := func(chunk object.EncodedChunk) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if cs != nil {
			routingIDs := make([]string, len(chunk.Shards))
			for i, shard := range chunk.Shards {
				if int(shard.Index) >= len(chunk.Ref.Shards) {
					return fmt.Errorf("chunk %d produced invalid shard index %d", chunk.Ref.Index, shard.Index)
				}
				routingIDs[i] = chunk.Ref.Shards[shard.Index].RoutingID
			}
			storeCtx, storeCancel := context.WithTimeout(ctx, 30*time.Minute)
			err := cs.DistributeAllShards(storeCtx, chunk.Shards, routingIDs, 365*24*3600)
			storeCancel()
			if err != nil {
				return err
			}
		} else {
			for _, shard := range chunk.Shards {
				if int(shard.Index) >= len(chunk.Ref.Shards) {
					return fmt.Errorf("chunk %d produced invalid shard index %d", chunk.Ref.Index, shard.Index)
				}
				routingID := chunk.Ref.Shards[shard.Index].RoutingID
				if err := localStore.Put(routingID, shard); err != nil {
					return fmt.Errorf("failed storing shard %d locally: %w", shard.Index, err)
				}
				stored, err := localStore.Get(routingID)
				if err != nil {
					return fmt.Errorf("failed verifying shard %d after local storage: %w", shard.Index, err)
				}
				if stored.Index != shard.Index || stored.Checksum != shard.Checksum {
					return fmt.Errorf("local shard %d verification mismatch", shard.Index)
				}
			}
		}

		return nil
	}
	pagedManifest, err := ingestAndCommitPagedManifest(ctx, pipeline, f, filepath.Base(filePath), manifestPath, kr, uint32(*pageSizeFlag), storeChunk, func(chunk object.EncodedChunk) error {
		if err := storeChunk(chunk); err != nil {
			return err
		}
		storedChunks++
		storedShards += len(chunk.Shards)
		fmt.Printf("\rStored %d chunks / %d data shards", storedChunks, storedShards)
		return nil
	})
	if err != nil {
		fmt.Println()
		return err
	}
	fmt.Println()
	fmt.Printf("Encrypted paged manifest committed to: %s (%d pages)\n", manifestPath, pagedManifest.Header.PageCount)

	if cs != nil && *publishCatalog {
		cat, err := loadOrCreateCatalog(id.NodeID(), kr.CatalogKey[:])
		if err != nil {
			return fmt.Errorf("object shards and encrypted manifest are stored, but the local catalog could not be loaded: %w", err)
		}
		if err := cat.AddPagedFile(pagedManifest); err != nil {
			return fmt.Errorf("object shards and encrypted paged manifest are stored, but the catalog entry is invalid: %w", err)
		}
		if err := saveCatalog(cat, kr.CatalogKey[:]); err != nil {
			return fmt.Errorf("object shards and encrypted manifest are stored, but the local catalog could not be committed: %w", err)
		}
		fmt.Printf("Publishing encrypted catalog to swarm (v%d, %d files)...\n", cat.Version, len(cat.Files))
		if err := catalog.DistributeCatalog(ctx, cs.Host, cs.DHT, cat, kr, cs.PeerIDs(), 0); err != nil {
			return fmt.Errorf("object shards and encrypted manifest are stored, but publishing the remote catalog failed: %w", err)
		}
		fmt.Println("Encrypted catalog successfully published to swarm!")
	}

	fmt.Println("\n=================================================================")
	fmt.Println("                     INGEST SUCCEEDED                           ")
	fmt.Println("=================================================================")
	fmt.Printf("Object ID:    %s\n", pagedManifest.Header.ObjectID)
	fmt.Printf("Total Size:   %d bytes\n", pagedManifest.Header.TotalSize)
	fmt.Printf("Total Chunks: %d\n", pagedManifest.Header.ChunkCount)
	metadataShards := uint64(pagedManifest.Header.PageCount) * uint64(erasure.DefaultTotalShards)
	fmt.Printf("Data Shards: %d (6 data + 4 parity per chunk)\n", storedShards)
	fmt.Printf("Manifest Pages: %d objects / %d shards\n", pagedManifest.Header.PageCount, metadataShards)
	return nil
}

// ingestAndCommitManifest writes the recovery manifest only after streaming
// completed and every sink call succeeded. Keeping this boundary in one helper
// makes it hard for an interrupted upload to replace a prior recovery point.
func ingestAndCommitManifest(ctx context.Context, pipeline *object.Pipeline, input io.Reader, logicalPath, manifestPath string, catalogKey []byte, sink func(object.EncodedChunk) error) (*object.Manifest, error) {
	manifest, err := pipeline.IngestStream(input, logicalPath, sink)
	if err != nil {
		return nil, fmt.Errorf("ingest failed before commit; no new manifest was persisted: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ingest canceled before manifest commit: %w", err)
	}
	manifestData, err := object.MarshalEncryptedManifest(manifest, catalogKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt manifest: %w", err)
	}
	if err := writeFileAtomic(manifestPath, manifestData, 0600); err != nil {
		return nil, fmt.Errorf("all object shards were stored, but encrypted manifest commit failed: %w", err)
	}
	return manifest, nil
}

// ingestAndCommitPagedManifest stores encrypted pages as ordinary FlowStore
// objects, then atomically writes their compact encrypted descriptor only
// after the input object and every metadata page have stored successfully.
func ingestAndCommitPagedManifest(ctx context.Context, pipeline *object.Pipeline, input io.Reader, logicalPath, manifestPath string, keyring *crypto.Keyring, pageSize uint32, pageChunkSink, dataChunkSink func(object.EncodedChunk) error) (*object.PagedManifest, error) {
	var pageManifests []*object.Manifest
	pageSink := func(pageIndex uint32, encryptedPage []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := object.UnmarshalEncryptedPage(encryptedPage, keyring.CatalogKey[:])
		if err != nil {
			return fmt.Errorf("validate encrypted manifest page %d: %w", pageIndex, err)
		}
		if page.PageIndex != pageIndex {
			return fmt.Errorf("manifest page callback index %d does not match page index %d", pageIndex, page.PageIndex)
		}
		if len(encryptedPage) == 0 || uint64(len(encryptedPage)) > uint64(^uint32(0)) {
			return fmt.Errorf("encrypted manifest page %d is too large to store as one chunk", pageIndex)
		}
		pagePipeline, err := object.NewPipeline(keyring, uint32(len(encryptedPage)), 0)
		if err != nil {
			return fmt.Errorf("create pipeline for manifest page %d: %w", pageIndex, err)
		}
		pagePath := fmt.Sprintf(".flowstore/manifest-pages/%s/%08d", page.ObjectID, pageIndex)
		pageManifest, err := pagePipeline.IngestStream(bytes.NewReader(encryptedPage), pagePath, pageChunkSink)
		if err != nil {
			return fmt.Errorf("store encrypted manifest page %d: %w", pageIndex, err)
		}
		if len(pageManifest.Chunks) != 1 {
			return fmt.Errorf("manifest page %d used %d data chunks, expected one", pageIndex, len(pageManifest.Chunks))
		}
		pageManifests = append(pageManifests, pageManifest)
		return nil
	}

	header, err := pipeline.IngestStreamPaged(input, logicalPath, pageSize, dataChunkSink, pageSink)
	if err != nil {
		return nil, fmt.Errorf("paged ingest failed before descriptor commit; no new manifest was persisted: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("paged ingest canceled before descriptor commit: %w", err)
	}
	pagedManifest := &object.PagedManifest{Header: *header, PageManifests: pageManifests}
	if err := object.ValidatePagedManifest(pagedManifest); err != nil {
		return nil, fmt.Errorf("paged ingest produced an invalid descriptor: %w", err)
	}
	manifestData, err := object.MarshalEncryptedPagedManifest(pagedManifest, keyring.CatalogKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt paged manifest descriptor: %w", err)
	}
	if err := writeFileAtomic(manifestPath, manifestData, 0600); err != nil {
		return nil, fmt.Errorf("all data and metadata-page shards were stored, but paged manifest commit failed: %w", err)
	}
	return pagedManifest, nil
}

func cmdAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	var peerFlags stringSlice
	fs.Var(&peerFlags, "peer", "Swarm peer multiaddress (can be repeated)")
	peersFlag := fs.String("peers", "", "Comma-separated list of peer multiaddresses")
	fs.Parse(normalizeArgs(args, nil))

	if fs.NArg() < 1 {
		fmt.Println("Usage: flow audit <manifest-file> [-peer <addr>]...")
		os.Exit(1)
	}

	manifestPath := fs.Arg(0)
	kr, _, err := loadKeyring()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	manifest, err := loadManifestFile(manifestPath, kr.CatalogKey[:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	peers := collectPeers(peerFlags, *peersFlag)
	var cs *network.ClientSession
	if len(peers) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s, err := network.NewDiscoveryClientSession(ctx, peers)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed connecting to peers for audit: %v\n", err)
			os.Exit(1)
		}
		cs = s
		defer cs.Close()
	}

	var localStore *storage.FileShardStore
	if cs == nil {
		store, err := storage.NewFileShardStore("./flownode-data/shards")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open shard store: %v\n", err)
			os.Exit(1)
		}
		defer store.Close()
		localStore = store
	}

	fmt.Printf("Auditing swarm health for object %s (%s)...\n", manifest.objectID(), manifest.logicalPath())
	totalChunks := 0
	healthyChunks := 0
	degradedChunks := 0
	criticalChunks := 0
	unavailableChunks := 0
	getter := func(routingID string) (*erasure.Shard, error) {
		if cs != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return cs.FetchShard(ctx, routingID)
		}
		return localStore.Get(routingID)
	}
	err = manifest.visitStoredChunks(kr, getter, func(chunk object.ChunkRef) error {
		present := 0
		for _, sRef := range chunk.Shards {
			if cs != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				has, _, _ := cs.ProbeShard(ctx, sRef.RoutingID, sRef.Checksum)
				cancel()
				if has {
					present++
				}
			} else if localStore != nil {
				if localStore.Has(sRef.RoutingID) {
					present++
				}
			}
		}
		totalChunks++

		switch {
		case present == len(chunk.Shards):
			healthyChunks++
		case present > 6:
			degradedChunks++
		case present == 6:
			criticalChunks++
		default:
			unavailableChunks++
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to inspect manifest chunks: %v\n", err)
		os.Exit(1)
	}

	healthPct := 0.0
	if totalChunks > 0 {
		healthPct = float64(healthyChunks) / float64(totalChunks) * 100.0
	}

	fmt.Println("=================================================================")
	fmt.Println("                 FLOWSTORE SWARM HEALTH REPORT                   ")
	fmt.Println("=================================================================")
	fmt.Printf("Object Path:         %s\n", manifest.logicalPath())
	fmt.Printf("Total Chunks:        %d\n", totalChunks)
	fmt.Printf("Healthy (10/10):     %d\n", healthyChunks)
	fmt.Printf("Degraded (7-9/10):   %d\n", degradedChunks)
	fmt.Printf("Critical (6/10):     %d\n", criticalChunks)
	fmt.Printf("Unavailable (<6/10): %d\n", unavailableChunks)
	fmt.Printf("Verified Health:     %.2f%%\n", healthPct)
	if unavailableChunks == 0 {
		fmt.Println("Status:              RECOVERABLE (100% data intact)")
	} else {
		fmt.Println("Status:              DATA LOSS DETECTED")
	}
}

func cmdRecover(args []string) error {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	var peerFlags stringSlice
	fs.Var(&peerFlags, "peer", "FlowStore DHT bootstrap peer multiaddress (can be repeated)")
	peersFlag := fs.String("peers", "", "Comma-separated list of FlowStore DHT bootstrap peer multiaddresses")
	if err := fs.Parse(normalizeArgs(args, nil)); err != nil {
		return err
	}

	if fs.NArg() < 2 {
		return errors.New("usage: flow recover <manifest-file> <output_path> [-peer <bootstrap-addr>]...")
	}

	manifestPath := fs.Arg(0)
	outputPath := fs.Arg(1)
	kr, _, err := loadKeyring()
	if err != nil {
		return err
	}
	manifest, err := loadManifestFile(manifestPath, kr.CatalogKey[:])
	if err != nil {
		return err
	}

	peers := collectPeers(peerFlags, *peersFlag)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var cs *network.ClientSession
	if len(peers) > 0 {
		connectCtx, connectCancel := context.WithTimeout(ctx, 30*time.Second)
		// A fresh recovery runner may know only one bootstrap peer. Join the
		// FlowStore DHT so FetchShard can discover peers holding each shard.
		s, err := network.NewDiscoveryClientSession(connectCtx, peers)
		connectCancel()
		if err != nil {
			return fmt.Errorf("failed connecting to swarm peers: %w", err)
		}
		cs = s
		defer cs.Close()
	}

	var localStore *storage.FileShardStore
	if cs == nil {
		store, err := storage.NewFileShardStore("./flownode-data/shards")
		if err != nil {
			return fmt.Errorf("failed to open shard store: %w", err)
		}
		defer store.Close()
		localStore = store
	}

	outputDir := filepath.Dir(outputPath)
	outF, err := os.CreateTemp(outputDir, "."+filepath.Base(outputPath)+".recover-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary recovery output beside %s: %w", outputPath, err)
	}
	tempPath := outF.Name()
	committed := false
	defer func() {
		_ = outF.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := outF.Chmod(0600); err != nil {
		return fmt.Errorf("failed to restrict permissions on temporary recovery output: %w", err)
	}

	getter := func(routingID string) (*erasure.Shard, error) {
		if cs != nil {
			fetchCtx, fetchCancel := context.WithTimeout(ctx, 10*time.Second)
			defer fetchCancel()
			return cs.FetchShard(fetchCtx, routingID)
		}
		return localStore.Get(routingID)
	}

	fmt.Printf("Reconstructing %s to %s...\n", manifest.logicalPath(), outputPath)
	if err := manifest.reconstruct(outF, kr, getter); err != nil {
		return fmt.Errorf("reconstruction failed; existing output was left unchanged: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("recovery canceled before output commit: %w", err)
	}
	if err := outF.Sync(); err != nil {
		return fmt.Errorf("failed syncing recovered data: %w", err)
	}
	if err := outF.Close(); err != nil {
		return fmt.Errorf("failed closing recovered data: %w", err)
	}
	if err := os.Rename(tempPath, outputPath); err != nil {
		return fmt.Errorf("recovery verified but failed to publish %s: %w", outputPath, err)
	}
	committed = true
	if runtime.GOOS != "windows" {
		directory, err := os.Open(outputDir)
		if err != nil {
			return fmt.Errorf("recovered output was renamed but its directory could not be opened for sync: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("recovered output was renamed but directory sync failed: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("recovered output was renamed but directory close failed: %w", closeErr)
		}
	}

	fmt.Println("SUCCESS: File reconstructed byte-perfect from surviving swarm shards!")
	return nil
}

func cmdRestore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	secretFlag := fs.String("secret", "", "Master recovery secret (FLOW-XXXX-...)")
	secretFileFlag := fs.String("secret-file", "", "Read the master recovery secret from a protected file")
	var peerFlags stringSlice
	fs.Var(&peerFlags, "peer", "Swarm peer multiaddress (can be repeated)")
	peersFlag := fs.String("peers", "", "Comma-separated list of peer multiaddresses")
	fs.Parse(normalizeArgs(args, nil))

	if fs.NArg() < 1 {
		fmt.Println("Usage: flow restore <output_dir> [-secret <FLOW-XXXX-...> | -secret-file <path>] -peer <addr>...")
		os.Exit(1)
	}

	outDir := fs.Arg(0)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	var code string
	if *secretFlag != "" && *secretFileFlag != "" {
		fmt.Fprintln(os.Stderr, "Error: use either -secret or -secret-file, not both.")
		os.Exit(1)
	}
	if *secretFileFlag != "" {
		secretInfo, err := os.Stat(*secretFileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to access recovery secret file: %v\n", err)
			os.Exit(1)
		}
		if runtime.GOOS != "windows" && secretInfo.Mode().Perm()&0077 != 0 {
			fmt.Fprintln(os.Stderr, "Error: recovery secret file must not be accessible by group or other users (use mode 0600 or stricter).")
			os.Exit(1)
		}
		secretBytes, err := os.ReadFile(*secretFileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read recovery secret file: %v\n", err)
			os.Exit(1)
		}
		code = strings.TrimSpace(string(secretBytes))
		if code == "" {
			fmt.Fprintln(os.Stderr, "Error: recovery secret file is empty.")
			os.Exit(1)
		}
	} else if *secretFlag != "" {
		code = *secretFlag
	} else {
		_, c, err := loadKeyring()
		if err != nil {
			fmt.Fprintf(os.Stderr, "No secret specified and no local identity: %v\n", err)
			os.Exit(1)
		}
		code = c
	}

	peers := collectPeers(peerFlags, *peersFlag)
	if len(peers) == 0 {
		fmt.Fprintln(os.Stderr, "Error: at least one -peer multiaddress is required for swarm restore.")
		os.Exit(1)
	}

	fmt.Println("=================================================================")
	fmt.Println("          FLOWSTORE ROOT SECRET SWARM RESTORATION                ")
	fmt.Println("=================================================================")
	fmt.Printf("Connecting to %d swarm peer(s)...\n", len(peers))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cs, err := network.NewDiscoveryClientSession(ctx, peers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Network error: %v\n", err)
		os.Exit(1)
	}
	defer cs.Close()

	fmt.Println("Connected. Hunting for encrypted catalog shards in the swarm...")
	cat, kr, err := catalog.RecoverCatalogFromSecret(ctx, cs.Host, cs.DHT, code, 0, cs.PeerIDs())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Catalog recovery failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=================================================================")
	fmt.Println("                 CATALOG RECONSTRUCTION SUCCESS                  ")
	fmt.Println("=================================================================")
	fmt.Printf("Catalog Owner:   %s\n", cat.OwnerID)
	fmt.Printf("Catalog Version: %d\n", cat.Version)
	fmt.Printf("Discovered:      %d file(s)\n", len(cat.Files))

	getter := func(routingID string) (*erasure.Shard, error) {
		fetchCtx, fCancel := context.WithTimeout(ctx, 10*time.Second)
		defer fCancel()
		return cs.FetchShard(fetchCtx, routingID)
	}

	restoreFailures := 0
	for path, entry := range cat.Files {
		targetFile := filepath.Join(outDir, filepath.Base(path))
		fmt.Printf("\nRestoring %s (%d bytes) -> %s...\n", path, entry.Size, targetFile)

		outF, err := os.Create(targetFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed creating file %s: %v\n", targetFile, err)
			restoreFailures++
			continue
		}

		if err := reconstructCatalogEntry(outF, entry, kr, getter); err != nil {
			if closeErr := outF.Close(); closeErr != nil {
				fmt.Fprintf(os.Stderr, "Failed closing incomplete output %s: %v\n", targetFile, closeErr)
			}
			fmt.Fprintf(os.Stderr, "Failed reconstructing %s: %v\n", path, err)
			restoreFailures++
			continue
		}
		if err := outF.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed closing restored output %s: %v\n", targetFile, err)
			restoreFailures++
			continue
		}
		fmt.Printf("  -> SUCCESS: %s restored byte-perfect!\n", targetFile)
	}

	if restoreFailures > 0 {
		fmt.Fprintf(os.Stderr, "\nRestore incomplete: %d of %d catalog file(s) failed.\n", restoreFailures, len(cat.Files))
		os.Exit(1)
	}
	fmt.Println("\nSwarm restoration complete! All files verified and restored.")
}

func cmdDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	var peerFlags stringSlice
	fs.Var(&peerFlags, "peer", "Swarm peer multiaddress (can be repeated)")
	peersFlag := fs.String("peers", "", "Comma-separated list of peer multiaddresses")
	fs.Parse(normalizeArgs(args, nil))

	if fs.NArg() < 1 {
		return fmt.Errorf("Usage: flow delete <manifest-file> [-peer <addr>]...")
	}
	manifestPath := fs.Arg(0)
	kr, _, err := loadKeyring()
	if err != nil {
		return err
	}
	manifest, err := loadManifestFile(manifestPath, kr.CatalogKey[:])
	if err != nil {
		return err
	}
	peers := collectPeers(peerFlags, *peersFlag)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	totalShards := 0
	if len(peers) == 0 {
		localStore, err := storage.NewFileShardStore("./flownode-data/shards")
		if err != nil {
			return fmt.Errorf("failed to open local shard store: %w", err)
		}
		defer localStore.Close()
		removed := 0
		err = manifest.visitStoredChunks(kr, localStore.Get, func(chunk object.ChunkRef) error {
			for _, sRef := range chunk.Shards {
				totalShards++
				if localStore.Has(sRef.RoutingID) {
					if err := localStore.Delete(sRef.RoutingID); err != nil {
						return fmt.Errorf("failed deleting local shard %s: %w", sRef.RoutingID, err)
					}
					removed++
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed traversing manifest while deleting local shards: %w", err)
		}
		fmt.Printf("Deleted %d/%d data and metadata shards for object %s from local store.\n", removed, totalShards, manifest.objectID())
		return nil
	}

	cs, err := network.NewDiscoveryClientSession(ctx, peers)
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	defer cs.Close()
	reclaimed := 0
	err = manifest.visitStoredChunks(kr, func(routingID string) (*erasure.Shard, error) {
		fetchCtx, fetchCancel := context.WithTimeout(ctx, 10*time.Second)
		defer fetchCancel()
		return cs.FetchShard(fetchCtx, routingID)
	}, func(chunk object.ChunkRef) error {
		for _, sRef := range chunk.Shards {
			totalShards++
			n, err := cs.DeleteShard(ctx, sRef.RoutingID)
			if err != nil {
				return fmt.Errorf("failed deleting shard %s: %w", sRef.RoutingID, err)
			}
			reclaimed += n
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed traversing manifest while deleting swarm shards: %w", err)
	}
	fmt.Printf("Reclaim requested for %d data and metadata shards (object %s); %d peer holdings removed.\n", totalShards, manifest.objectID(), reclaimed)
	if cs.DHT != nil {
		fmt.Printf("DHT provider records cannot be withdrawn immediately with the current libp2p Kademlia API; stale records expire within about %s.\n", network.DHTProviderRecordValidity)
	}
	return nil
}

func cmdRepairStatus(args []string) {
	fs := flag.NewFlagSet("repair-status", flag.ExitOnError)
	var peerFlags stringSlice
	fs.Var(&peerFlags, "peer", "Swarm peer multiaddress (can be repeated)")
	peersFlag := fs.String("peers", "", "Comma-separated list of peer multiaddresses")
	reannounce := fs.Bool("reannounce", false, "Ask the peer to re-announce held shards on the DHT")
	fs.Parse(normalizeArgs(args, map[string]bool{"reannounce": true}))

	peers := collectPeers(peerFlags, *peersFlag)
	if fs.NArg() == 1 && len(peers) == 0 {
		peers = []string{fs.Arg(0)}
	}
	if len(peers) == 0 {
		fmt.Println("Usage: flow repair-status <peer_multiaddr> [-reannounce]")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := network.NewClientSession(ctx, peers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Network error: %v\n", err)
		os.Exit(1)
	}
	defer cs.Close()
	for _, p := range cs.Peers {
		rCtx, rCancel := context.WithTimeout(ctx, 10*time.Second)
		resp, err := cs.RepairStatus(rCtx, p.ID, nil, *reannounce)
		rCancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Peer %s repair-status failed: %v\n", p.ID, err)
			continue
		}
		fmt.Printf("Peer %s: %d shards, %d bytes used / %d quota, domain %s, re-announced %d\n",
			p.ID, resp.ShardCount, resp.UsedBytes, resp.QuotaBytes, resp.FailureDomain, resp.Reannounced)
	}
}
