"""
RAG Engine — LangChain + LlamaIndex + SentenceTransformers + ChromaDB

Indexes the two regulatory PDFs already in the repo:
  - Nigeria_Data_Protection_Act_2023.pdf
  - NDP-ACT-GAID-2025-MARCH-20TH.pdf

On startup: chunks → embeds → stores in ChromaDB.
On query: semantic retrieval → grounded Gemini response with article citations.
"""
import os
import logging
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── PDF paths ──────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent.parent
PDF_FILES = [
    BASE_DIR / "Nigeria_Data_Protection_Act_2023.pdf",
    BASE_DIR / "NDP-ACT-GAID-2025-MARCH-20TH.pdf",
]
CHROMA_DIR = str(BASE_DIR / "chroma_db")
COLLECTION_NAME = "carbot_regulatory"

EMBEDDING_MODEL = "all-MiniLM-L6-v2"
CHUNK_SIZE = 800
CHUNK_OVERLAP = 100
TOP_K = 5


# ── Data models ────────────────────────────────────────────────────────────────
@dataclass
class Citation:
    source: str          # filename / framework name
    page: int            # page number in PDF
    article: str         # e.g. "Article 25" or "Section 4"
    text: str            # the retrieved clause excerpt


@dataclass
class RAGResult:
    answer: str
    citations: List[Citation] = field(default_factory=list)
    grounded: bool = False
    model_used: str = "gemini"


# ── RAGEngine ─────────────────────────────────────────────────────────────────
class RAGEngine:
    """
    Semantic retrieval pipeline over the Nigerian regulatory PDF corpus.
    Uses SentenceTransformers for embeddings and ChromaDB for storage.
    Falls back gracefully when optional deps are missing.
    """

    def __init__(self):
        self._ready = False
        self._vectorstore = None
        self._embeddings = None
        self._try_init()

    def _try_init(self):
        """Initialise the embedding model and ChromaDB. Fail soft."""
        try:
            from sentence_transformers import SentenceTransformer
            import chromadb

            self._embeddings = SentenceTransformer(EMBEDDING_MODEL)
            self._chroma_client = chromadb.PersistentClient(path=CHROMA_DIR)
            self._collection = self._chroma_client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
            self._ready = True
            logger.info("RAG engine initialised. ChromaDB ready at %s", CHROMA_DIR)
        except ImportError as e:
            logger.warning(
                "RAG engine disabled — missing dependency (%s). "
                "Install: sentence-transformers chromadb pypdf",
                e,
            )
        except Exception as e:
            logger.error("RAG engine init failed: %s", e, exc_info=True)

    # ── Indexing ───────────────────────────────────────────────────────────────

    def index_documents(self, force: bool = False) -> int:
        """
        Index all regulatory PDFs into ChromaDB.
        Skips if already indexed (unless force=True).
        Returns number of chunks added.
        """
        if not self._ready:
            logger.warning("RAG engine not ready — skipping indexing.")
            return 0

        existing_count = self._collection.count()
        if existing_count > 0 and not force:
            logger.info(
                "Regulatory corpus already indexed (%d chunks). Skipping.", existing_count
            )
            return existing_count

        total = 0
        for pdf_path in PDF_FILES:
            if not pdf_path.exists():
                logger.warning("PDF not found: %s — skipping.", pdf_path)
                continue
            chunks = self._chunk_pdf(pdf_path)
            self._embed_and_store(chunks, str(pdf_path.name))
            total += len(chunks)
            logger.info("Indexed %d chunks from %s", len(chunks), pdf_path.name)

        return total

    def _chunk_pdf(self, pdf_path: Path) -> List[dict]:
        """Load and chunk a PDF into text segments with metadata."""
        try:
            from pypdf import PdfReader
        except ImportError:
            logger.error("pypdf not installed. Run: pip install pypdf")
            return []

        reader = PdfReader(str(pdf_path))
        chunks = []
        source_name = self._source_label(pdf_path.name)

        for page_num, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""
            text = text.strip()
            if not text:
                continue

            # Split page into overlapping chunks
            for i in range(0, len(text), CHUNK_SIZE - CHUNK_OVERLAP):
                chunk_text = text[i : i + CHUNK_SIZE]
                if len(chunk_text) < 50:
                    continue
                article = self._extract_article_reference(chunk_text)
                chunks.append(
                    {
                        "text": chunk_text,
                        "source": source_name,
                        "page": page_num,
                        "article": article,
                        "filename": pdf_path.name,
                    }
                )

        return chunks

    def _embed_and_store(self, chunks: List[dict], filename: str):
        """Embed chunks and upsert into ChromaDB."""
        if not chunks:
            return

        texts = [c["text"] for c in chunks]
        embeddings = self._embeddings.encode(texts, show_progress_bar=False).tolist()

        ids = [f"{filename}_{i}" for i in range(len(chunks))]
        metadatas = [
            {k: v for k, v in c.items() if k != "text"}
            for c in chunks
        ]

        self._collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=texts,
            metadatas=metadatas,
        )

    # ── Retrieval ──────────────────────────────────────────────────────────────

    def retrieve(self, query: str, k: int = TOP_K) -> List[Citation]:
        """
        Semantic similarity search over the indexed regulatory corpus.
        Returns the top-k most relevant clause excerpts with citations.
        """
        if not self._ready or self._collection.count() == 0:
            return []

        try:
            query_embedding = self._embeddings.encode([query]).tolist()
            results = self._collection.query(
                query_embeddings=query_embedding,
                n_results=k,
                include=["documents", "metadatas", "distances"],
            )

            citations = []
            for doc, meta in zip(
                results["documents"][0], results["metadatas"][0]
            ):
                citations.append(
                    Citation(
                        source=meta.get("source", "Unknown"),
                        page=meta.get("page", 0),
                        article=meta.get("article", ""),
                        text=doc[:400],  # truncate for response
                    )
                )
            return citations
        except Exception as e:
            logger.error("RAG retrieval error: %s", e)
            return []

    # ── Grounded Generation ────────────────────────────────────────────────────

    async def generate_grounded_response(
        self,
        query: str,
        audit_context: str,
        history: List[dict],
        api_key: str,
    ) -> RAGResult:
        """
        Full RAG pipeline:
          1. Retrieve relevant clauses
          2. Build grounded system prompt
          3. Generate via LLM Router (Gemini → Mistral → Llama3 → Phi3)
          4. Return answer + citations
        """
        citations = self.retrieve(query)

        # Build grounded context from retrieved clauses
        if citations:
            clause_context = "\n\n".join(
                f"[{c.source} | {c.article} | Page {c.page}]\n{c.text}"
                for c in citations
            )
        else:
            clause_context = "No specific clauses retrieved. Answer from general knowledge."

        system_prompt = f"""You are an expert AI compliance advisor for CAR-Bot, specialising in Nigerian data protection law.

REGULATORY CONTEXT (retrieved from official documents):
{clause_context}

AUDIT CONTEXT:
{audit_context}

INSTRUCTIONS:
- Answer the user's question using the regulatory context above
- Cite the specific article/section when referencing a rule (e.g. "NDPA 2023 Article 25 states...")
- Be concise — 2-3 paragraphs unless the user asks for detail
- If the retrieved context does not cover the question, say so clearly
- Never fabricate article numbers or clause content
"""
        # Try Gemini first, then fall back via LLM Router
        try:
            from app.core.llm_router import LLMRouter
            router = LLMRouter(api_key=api_key)
            answer = await router.generate(
                system_prompt=system_prompt,
                user_message=query,
                history=history,
                task="compliance_qa",
            )
            model = router.last_model_used
        except Exception as e:
            logger.error("LLM Router failed: %s", e)
            answer = "I was unable to generate a response at this time. Please try again."
            model = "none"

        return RAGResult(
            answer=answer,
            citations=citations,
            grounded=len(citations) > 0,
            model_used=model,
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _source_label(filename: str) -> str:
        mapping = {
            "Nigeria_Data_Protection_Act_2023.pdf": "NDPA 2023",
            "NDP-ACT-GAID-2025-MARCH-20TH.pdf": "GAID 2025",
        }
        return mapping.get(filename, filename)

    @staticmethod
    def _extract_article_reference(text: str) -> str:
        """Extract the first article/section reference from text."""
        import re
        patterns = [
            r"Article\s+\d+[A-Za-z]?",
            r"Section\s+\d+[\(\)\d]*",
            r"Part\s+[IVXLC]+",
            r"Clause\s+\d+",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)
        return ""

    @property
    def is_ready(self) -> bool:
        return self._ready

    @property
    def document_count(self) -> int:
        if not self._ready:
            return 0
        return self._collection.count()


# ── Singleton ──────────────────────────────────────────────────────────────────
_rag_engine: Optional[RAGEngine] = None


def get_rag_engine() -> RAGEngine:
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = RAGEngine()
    return _rag_engine


def get_rag_engine_if_loaded() -> Optional[RAGEngine]:
    return _rag_engine
